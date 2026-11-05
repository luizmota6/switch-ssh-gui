//! Transferência de arquivos por SCP em sessão SSH própria (não interfere no terminal).
//!
//! Exige que a chave do host já esteja confirmada (fingerprint salvo no perfil):
//! a primeira conexão deve ser feita pelo terminal, onde o usuário confere o fingerprint.

use crate::ssh::{authenticate, connect_tcp, handshake, verify_known, Auth, FromWorker};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;

const CHUNK: usize = 32 * 1024;

#[derive(Clone, Copy, PartialEq)]
pub enum Direction {
    /// Computador -> switch
    Upload,
    /// Switch -> computador
    Download,
}

pub struct ScpJob {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub fingerprint: String,
    pub direction: Direction,
    pub local: PathBuf,
    /// Caminho no switch, repassado como está (ex.: `flash:/config.txt`, `/cfg/startup`).
    pub remote: String,
}

pub enum ScpEvent {
    Status(String),
    Progress { done: u64, total: u64 },
    Done(String),
    Error(String),
}

pub struct ScpHandle {
    pub rx: Receiver<ScpEvent>,
    cancel: Arc<AtomicBool>,
}

impl ScpHandle {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

pub fn spawn(job: ScpJob, ctx: eframe::egui::Context) -> ScpHandle {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = cancel.clone();
    thread::Builder::new()
        .name("scp-worker".into())
        .spawn(move || {
            let emit = |ev: ScpEvent| {
                let _ = tx.send(ev);
                ctx.request_repaint();
            };
            let ev = match run(&job, &flag, &emit) {
                Ok(msg) => ScpEvent::Done(msg),
                Err(e) => ScpEvent::Error(e),
            };
            emit(ev);
        })
        .expect("falha ao criar thread SCP");
    ScpHandle { rx, cancel }
}

fn run(job: &ScpJob, cancel: &AtomicBool, emit: &dyn Fn(ScpEvent)) -> Result<String, String> {
    // reaproveita o connect_tcp, que reporta status como FromWorker
    let status = |ev: FromWorker| {
        if let FromWorker::Status(s) = ev {
            emit(ScpEvent::Status(s));
        }
    };
    let tcp = connect_tcp(&job.host, job.port, &status)?;
    let (sess, fingerprint, _) = handshake(tcp, &job.host, job.port, &job.user)?;
    verify_known(&job.fingerprint, &fingerprint)?;
    emit(ScpEvent::Status("Autenticando…".into()));
    authenticate(&sess, &job.user, &job.auth)?;
    sess.set_timeout(60_000);

    let res = match job.direction {
        Direction::Upload => upload(&sess, job, cancel, emit),
        Direction::Download => download(&sess, job, cancel, emit),
    };
    let _ = sess.disconnect(None, "bye", None);
    res
}

fn upload(sess: &ssh2::Session, job: &ScpJob, cancel: &AtomicBool, emit: &dyn Fn(ScpEvent)) -> Result<String, String> {
    let mut file = File::open(&job.local)
        .map_err(|e| format!("Não foi possível abrir {}: {e}", job.local.display()))?;
    let total = file.metadata().map_err(|e| e.to_string())?.len();
    emit(ScpEvent::Status(format!("Enviando para {}…", job.remote)));
    let mut ch = sess
        .scp_send(Path::new(&job.remote), 0o644, total, None)
        .map_err(|e| scp_hint(format!("O switch recusou o envio SCP: {e}")))?;

    let mut buf = vec![0u8; CHUNK];
    let mut done = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = ch.close();
            return Err("Envio cancelado pelo usuário (o arquivo no switch pode ter ficado incompleto).".into());
        }
        let n = file.read(&mut buf).map_err(|e| format!("Erro lendo arquivo local: {e}"))?;
        if n == 0 {
            break;
        }
        ch.write_all(&buf[..n]).map_err(|e| format!("Erro no envio: {e}"))?;
        done += n as u64;
        emit(ScpEvent::Progress { done, total });
    }
    // sequência de encerramento exigida pelo protocolo SCP
    ch.send_eof().map_err(|e| format!("Erro finalizando envio: {e}"))?;
    let _ = ch.wait_eof();
    let _ = ch.close();
    let _ = ch.wait_close();
    Ok(format!("Enviado: {} → {} ({})", job.local.display(), job.remote, human(total)))
}

fn download(sess: &ssh2::Session, job: &ScpJob, cancel: &AtomicBool, emit: &dyn Fn(ScpEvent)) -> Result<String, String> {
    emit(ScpEvent::Status(format!("Baixando {}…", job.remote)));
    let (mut ch, stat) = sess
        .scp_recv(Path::new(&job.remote))
        .map_err(|e| scp_hint(format!("O switch recusou o download SCP: {e}")))?;
    let total = stat.size();

    // grava em .part e só renomeia no final: nunca deixa arquivo truncado com o nome final
    let mut part = job.local.clone().into_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    let mut out = File::create(&part).map_err(|e| format!("Não foi possível criar {}: {e}", part.display()))?;

    let res = (|| {
        let mut buf = vec![0u8; CHUNK];
        let mut done = 0u64;
        while done < total {
            if cancel.load(Ordering::Relaxed) {
                return Err("Download cancelado pelo usuário.".to_string());
            }
            let want = ((total - done) as usize).min(CHUNK);
            match ch.read(&mut buf[..want]) {
                Ok(0) => return Err(format!("Conexão encerrada após {} de {}", human(done), human(total))),
                Ok(n) => {
                    out.write_all(&buf[..n]).map_err(|e| format!("Erro gravando arquivo: {e}"))?;
                    done += n as u64;
                    emit(ScpEvent::Progress { done, total });
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("Erro no download: {e}")),
            }
        }
        out.flush().map_err(|e| e.to_string())?;
        Ok(())
    })();
    drop(out);
    let _ = ch.close();

    if let Err(e) = res {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    let _ = fs::remove_file(&job.local);
    fs::rename(&part, &job.local).map_err(|e| format!("Erro ao renomear {}: {e}", part.display()))?;
    Ok(format!("Baixado: {} → {} ({})", job.remote, job.local.display(), human(total)))
}

fn scp_hint(msg: String) -> String {
    format!(
        "{msg}\nVerifique se o servidor SCP está habilitado no switch \
         (ex.: Cisco 'ip scp server enable', Aruba 'ip ssh filetransfer') \
         e se o caminho remoto existe e tem permissão."
    )
}

pub fn human(n: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::human;

    #[test]
    fn tamanhos_legiveis() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(5 * 1024 * 1024), "5.0 MB");
    }
}
