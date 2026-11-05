//! Monitor de recursos de servidores Linux (CPU, memória, disco, rede, carga, uptime),
//! no estilo da barra de monitoramento do MobaXterm.
//!
//! Usa uma conexão SSH própria e silenciosa: a cada intervalo executa um comando
//! (canal "exec") que lê o /proc — nada é digitado no terminal do usuário.
//! Em equipamentos que não são Linux (switches), a primeira leitura falha e o
//! monitor se desliga sozinho informando "não suportado".

use crate::ssh::{authenticate, connect_tcp, handshake, verify_known, Auth, FromWorker};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub const INTERVAL: Duration = Duration::from_secs(2);
const SEP: &str = "@@MON@@";

/// Comando POSIX (funciona em sh/bash/ash): seções separadas por marcador.
fn probe_command() -> String {
    format!(
        "LC_ALL=C; export LC_ALL; \
         head -n 1 /proc/stat; echo {SEP}; \
         cat /proc/meminfo; echo {SEP}; \
         cat /proc/loadavg; echo {SEP}; \
         cat /proc/uptime; echo {SEP}; \
         df -Pk / | tail -n 1; echo {SEP}; \
         cat /proc/net/dev; echo {SEP}; \
         nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo"
    )
}

/// Leitura bruta (contadores acumulados) de um instante.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sample {
    pub cpu_total: u64,
    pub cpu_idle: u64,
    pub mem_total_kb: u64,
    pub mem_avail_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
    pub load: [f32; 3],
    pub uptime_s: u64,
    pub disk_total_kb: u64,
    pub disk_used_kb: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub cores: u32,
}

/// Valores prontos para exibir.
#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// None na primeira leitura (CPU e rede precisam de duas amostras).
    pub cpu_pct: Option<f32>,
    pub mem_used_kb: u64,
    pub mem_total_kb: u64,
    pub swap_used_kb: u64,
    pub swap_total_kb: u64,
    pub load: [f32; 3],
    pub uptime_s: u64,
    pub disk_used_kb: u64,
    pub disk_total_kb: u64,
    pub rx_per_s: Option<f64>,
    pub tx_per_s: Option<f64>,
    pub cores: u32,
    /// Histórico recente de CPU (%) para o mini gráfico.
    pub cpu_history: Vec<f32>,
}

impl Stats {
    pub fn mem_pct(&self) -> f32 {
        pct(self.mem_used_kb, self.mem_total_kb)
    }
    pub fn disk_pct(&self) -> f32 {
        pct(self.disk_used_kb, self.disk_total_kb)
    }
}

fn pct(used: u64, total: u64) -> f32 {
    if total == 0 {
        0.0
    } else {
        used as f32 * 100.0 / total as f32
    }
}

/// Interpreta a saída do comando. Erro = não é Linux (ou faltou /proc).
pub fn parse(out: &str) -> Result<Sample, String> {
    let parts: Vec<&str> = out.split(SEP).map(str::trim).collect();
    let first_line = out.lines().next().unwrap_or("").trim().to_string();
    let not_linux = || {
        if first_line.is_empty() {
            "sem resposta ao comando de monitoramento".to_string()
        } else {
            format!("resposta: \"{}\"", first_line.chars().take(60).collect::<String>())
        }
    };
    if parts.len() < 7 {
        return Err(not_linux());
    }

    // /proc/stat: "cpu  user nice system idle iowait irq softirq steal ..."
    let cpu: Vec<u64> = parts[0]
        .strip_prefix("cpu")
        .ok_or_else(not_linux)?
        .split_whitespace()
        .filter_map(|v| v.parse().ok())
        .collect();
    if cpu.len() < 4 {
        return Err(not_linux());
    }
    let cpu_total: u64 = cpu.iter().take(8).sum();
    let cpu_idle = cpu[3] + cpu.get(4).copied().unwrap_or(0);

    let mut s = Sample { cpu_total, cpu_idle, ..Default::default() };

    // /proc/meminfo (kB)
    let mut free = 0;
    let mut buffers = 0;
    let mut cached = 0;
    let mut avail = None;
    for l in parts[1].lines() {
        let mut it = l.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next().and_then(|v| v.parse::<u64>().ok())) else { continue };
        match k {
            "MemTotal:" => s.mem_total_kb = v,
            "MemAvailable:" => avail = Some(v),
            "MemFree:" => free = v,
            "Buffers:" => buffers = v,
            "Cached:" => cached = v,
            "SwapTotal:" => s.swap_total_kb = v,
            "SwapFree:" => s.swap_free_kb = v,
            _ => {}
        }
    }
    // kernels antigos não têm MemAvailable
    s.mem_avail_kb = avail.unwrap_or(free + buffers + cached);

    // /proc/loadavg
    for (i, v) in parts[2].split_whitespace().take(3).enumerate() {
        s.load[i] = v.parse().unwrap_or(0.0);
    }
    // /proc/uptime
    s.uptime_s = parts[3]
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0) as u64;
    // df -Pk /: "fs blocos usados disponíveis capacidade montagem"
    let df: Vec<&str> = parts[4].split_whitespace().collect();
    if df.len() >= 4 {
        s.disk_total_kb = df[1].parse().unwrap_or(0);
        s.disk_used_kb = df[2].parse().unwrap_or(0);
    }
    // /proc/net/dev: "  eth0: rx_bytes ... (8 campos) tx_bytes ..." — soma tudo menos lo
    for l in parts[5].lines() {
        let Some((iface, rest)) = l.split_once(':') else { continue };
        if iface.trim() == "lo" {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
        if f.len() >= 9 {
            s.net_rx += f[0];
            s.net_tx += f[8];
        }
    }
    s.cores = parts[6].split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);

    if s.mem_total_kb == 0 {
        return Err(not_linux());
    }
    Ok(s)
}

/// Calcula os valores a exibir a partir da amostra atual e (se houver) da anterior.
pub fn compute(prev: Option<(&Sample, Instant)>, cur: &Sample, now: Instant) -> Stats {
    let mut st = Stats {
        mem_used_kb: cur.mem_total_kb.saturating_sub(cur.mem_avail_kb),
        mem_total_kb: cur.mem_total_kb,
        swap_used_kb: cur.swap_total_kb.saturating_sub(cur.swap_free_kb),
        swap_total_kb: cur.swap_total_kb,
        load: cur.load,
        uptime_s: cur.uptime_s,
        disk_used_kb: cur.disk_used_kb,
        disk_total_kb: cur.disk_total_kb,
        cores: cur.cores,
        ..Default::default()
    };
    if let Some((p, t)) = prev {
        let dt = cur.cpu_total.saturating_sub(p.cpu_total);
        let di = cur.cpu_idle.saturating_sub(p.cpu_idle);
        if dt > 0 {
            st.cpu_pct = Some(((dt - di.min(dt)) as f32 * 100.0 / dt as f32).clamp(0.0, 100.0));
        }
        let secs = now.duration_since(t).as_secs_f64();
        // contador zerado (reboot/troca de interface) não vira taxa negativa
        if secs > 0.0 && cur.net_rx >= p.net_rx && cur.net_tx >= p.net_tx {
            st.rx_per_s = Some((cur.net_rx - p.net_rx) as f64 / secs);
            st.tx_per_s = Some((cur.net_tx - p.net_tx) as f64 / secs);
        }
    }
    st
}

pub fn human_bytes(b: f64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", U[i])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn human_uptime(s: u64) -> String {
    let (d, h, m) = (s / 86_400, (s % 86_400) / 3600, (s % 3600) / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}min")
    } else {
        format!("{m}min")
    }
}

// ---------------- worker ----------------

pub struct MonitorJob {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub fingerprint: String,
}

pub enum MonitorEvent {
    Stats(Stats),
    /// Equipamento não é Linux / não aceita o comando: monitor encerrado.
    Unsupported(String),
    /// Falha de conexão/autenticação: monitor encerrado.
    Error(String),
}

pub struct MonitorHandle {
    pub rx: Receiver<MonitorEvent>,
    stop: Arc<AtomicBool>,
}

impl MonitorHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn spawn(job: MonitorJob, ctx: eframe::egui::Context) -> MonitorHandle {
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    thread::Builder::new()
        .name("monitor-worker".into())
        .spawn(move || {
            let emit = |ev: MonitorEvent| {
                let ok = tx.send(ev).is_ok();
                ctx.request_repaint();
                ok
            };
            if let Err(ev) = run(&job, &flag, &emit) {
                if !flag.load(Ordering::Relaxed) {
                    emit(ev);
                }
            }
        })
        .expect("falha ao criar thread do monitor");
    MonitorHandle { rx, stop }
}

fn run(job: &MonitorJob, stop: &AtomicBool, emit: &dyn Fn(MonitorEvent) -> bool) -> Result<(), MonitorEvent> {
    let quiet = |_: FromWorker| {};
    let tcp = connect_tcp(&job.host, job.port, &quiet).map_err(MonitorEvent::Error)?;
    let (sess, fp, _) = handshake(tcp, &job.host, job.port, &job.user).map_err(MonitorEvent::Error)?;
    verify_known(&job.fingerprint, &fp).map_err(MonitorEvent::Error)?;
    authenticate(&sess, &job.user, &job.auth).map_err(MonitorEvent::Error)?;
    sess.set_timeout(10_000);
    sess.set_keepalive(true, 30);

    let cmd = probe_command();
    let mut prev: Option<(Sample, Instant)> = None;
    let mut history: Vec<f32> = Vec::new();
    let mut first = true;
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let out = exec(&sess, &cmd);
        let sample = match out.and_then(|o| parse(&o)) {
            Ok(s) => s,
            // já funcionou antes: falha passageira, tenta de novo no próximo ciclo
            Err(_) if !first => {
                sleep_until(started + INTERVAL, stop);
                continue;
            }
            Err(e) => return Err(MonitorEvent::Unsupported(e)),
        };
        first = false;
        let now = Instant::now();
        let mut st = compute(prev.as_ref().map(|(s, t)| (s, *t)), &sample, now);
        if let Some(c) = st.cpu_pct {
            history.push(c);
            if history.len() > 60 {
                history.remove(0);
            }
        }
        st.cpu_history = history.clone();
        if !emit(MonitorEvent::Stats(st)) {
            break; // UI descartou o monitor
        }
        prev = Some((sample, now));
        sleep_until(started + INTERVAL, stop);
    }
    let _ = sess.disconnect(None, "bye", None);
    Ok(())
}

fn exec(sess: &ssh2::Session, cmd: &str) -> Result<String, String> {
    let mut ch = sess.channel_session().map_err(|e| format!("canal recusado: {e}"))?;
    ch.exec(cmd).map_err(|e| format!("exec recusado: {e}"))?;
    let mut out = String::new();
    ch.read_to_string(&mut out).map_err(|e| format!("erro de leitura: {e}"))?;
    let _ = ch.wait_close();
    Ok(out)
}

fn sleep_until(t: Instant, stop: &AtomicBool) {
    while Instant::now() < t && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(cpu: &str, rx: u64, tx: u64) -> String {
        format!(
            "{cpu}\n{SEP}\nMemTotal:        4000000 kB\nMemFree:          500000 kB\nMemAvailable:    3000000 kB\n\
             SwapTotal:       1000000 kB\nSwapFree:         750000 kB\n{SEP}\n0.52 0.40 0.30 1/234 5678\n{SEP}\n\
             93784.12 180000.00\n{SEP}\n/dev/sda1 20000000 5000000 15000000 25% /\n{SEP}\n\
             Inter-|   Receive                                                |  Transmit\n \
             face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    \
             lo: 999999 10 0 0 0 0 0 0 999999 10 0 0 0 0 0 0\n  \
             eth0: {rx} 100 0 0 0 0 0 0 {tx} 100 0 0 0 0 0 0\n{SEP}\n4\n"
        )
    }

    #[test]
    fn interpreta_linux() {
        let s = parse(&out("cpu  100 0 100 700 100 0 0 0 0 0", 1000, 500)).unwrap();
        assert_eq!(s.cpu_total, 1000);
        assert_eq!(s.cpu_idle, 800);
        assert_eq!(s.mem_total_kb, 4_000_000);
        assert_eq!(s.mem_avail_kb, 3_000_000);
        assert_eq!(s.load, [0.52, 0.40, 0.30]);
        assert_eq!(s.uptime_s, 93784);
        assert_eq!((s.disk_total_kb, s.disk_used_kb), (20_000_000, 5_000_000));
        assert_eq!((s.net_rx, s.net_tx), (1000, 500)); // lo ignorada
        assert_eq!(s.cores, 4);
    }

    #[test]
    fn calcula_cpu_e_rede() {
        let t0 = Instant::now();
        let a = parse(&out("cpu  100 0 100 700 100 0 0 0 0 0", 1000, 500)).unwrap();
        // +1000 de CPU, dos quais 250 ociosos -> 75%
        let b = parse(&out("cpu  500 0 450 900 150 0 0 0 0 0", 1000 + 4096, 500 + 2048)).unwrap();
        let st = compute(Some((&a, t0)), &b, t0 + Duration::from_secs(2));
        assert!((st.cpu_pct.unwrap() - 75.0).abs() < 0.01);
        assert_eq!(st.rx_per_s, Some(2048.0));
        assert_eq!(st.tx_per_s, Some(1024.0));
        assert_eq!(st.mem_used_kb, 1_000_000);
        assert!((st.mem_pct() - 25.0).abs() < 0.01);
        assert!((st.disk_pct() - 25.0).abs() < 0.01);
        assert_eq!(st.swap_used_kb, 250_000);
        // primeira leitura: sem CPU/rede ainda
        assert!(compute(None, &a, t0).cpu_pct.is_none());
    }

    #[test]
    fn switch_nao_suportado() {
        let e = parse("% Invalid input detected at '^' marker.\n").unwrap_err();
        assert!(e.contains("Invalid input"));
        assert!(parse("").is_err());
    }

    #[test]
    fn formatos() {
        assert_eq!(human_bytes(512.0), "512 B");
        assert_eq!(human_bytes(1536.0), "1.5 KB");
        assert_eq!(human_uptime(93784), "1d 2h");
        assert_eq!(human_uptime(3700), "1h 1min");
    }
}
