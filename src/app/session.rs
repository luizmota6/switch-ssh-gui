//! Uma sessão de terminal (SSH ou Telnet) com conexão, telas, log e backup próprios.
//! O app mantém várias ao mesmo tempo (abas / telas divididas).

use crate::backup::Backup;
use crate::config::{logs_dir, Profile};
use crate::monitor::{MonitorEvent, MonitorHandle, Stats};
use crate::ssh::{Auth, FromWorker, SshHandle, ToWorker};
use crate::term::Terminal;
use crate::vterm::VTerm;
use eframe::egui::Color32;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(PartialEq)]
pub enum ConnState {
    Disconnected,
    Connecting,
    HostKey { fingerprint: String, key_type: String },
    Connected,
}

/// Estado do monitor de recursos (CPU/memória/uptime) da sessão.
pub enum MonitorState {
    Off,
    Starting,
    Running(Stats),
    /// Não é Linux (switch etc.): desligado, com o motivo.
    Unsupported(String),
    Failed(String),
}

/// O que aconteceu numa sessão e precisa ser tratado pelo app.
pub enum SessionEvent {
    /// Login concluído (o app pode iniciar o monitor de recursos).
    Connected,
    Status(String),
    Error(String),
    /// Chave do host aceita pelo usuário: salvar em known_hosts.
    HostKeyAccepted { host_key_id: String, fingerprint: String },
    /// Conexão encerrada (`backup_lost` = havia backup em andamento).
    Closed { backup_lost: bool },
}

pub struct Session {
    pub id: u64,
    pub profile: Profile,
    pub conn: Option<SshHandle>,
    pub state: ConnState,
    pub status: String,
    pub term: Terminal,
    pub vterm: VTerm,
    pub log: Option<(BufWriter<File>, PathBuf)>,
    pub backup: Option<Backup>,
    pub focus_term: bool,
    /// Credenciais usadas no login (o monitor abre a própria conexão com elas).
    pub auth: Option<Auth>,
    pub monitor: Option<MonitorHandle>,
    pub monitor_state: MonitorState,
}

impl Session {
    pub fn new(id: u64, profile: Profile, cols: u16, rows: u16) -> Self {
        Self {
            id,
            profile,
            conn: None,
            state: ConnState::Disconnected,
            status: "Desconectado".into(),
            term: Terminal::new(50_000),
            vterm: VTerm::with_id(cols, rows, eframe::egui::Id::new(("vterm", id))),
            log: None,
            backup: None,
            focus_term: false,
            auth: None,
            monitor: None,
            monitor_state: MonitorState::Off,
        }
    }

    pub fn stop_monitor(&mut self) {
        if let Some(m) = self.monitor.take() {
            m.stop();
        }
        if matches!(self.monitor_state, MonitorState::Starting | MonitorState::Running(_)) {
            self.monitor_state = MonitorState::Off;
        }
    }

    fn poll_monitor(&mut self) {
        let Some(m) = &self.monitor else { return };
        for ev in m.rx.try_iter().collect::<Vec<_>>() {
            match ev {
                MonitorEvent::Stats(st) => self.monitor_state = MonitorState::Running(st),
                MonitorEvent::Unsupported(e) => {
                    self.monitor_state = MonitorState::Unsupported(e);
                    self.monitor = None;
                    return;
                }
                MonitorEvent::Error(e) => {
                    self.monitor_state = MonitorState::Failed(e);
                    self.monitor = None;
                    return;
                }
            }
        }
    }

    pub fn title(&self) -> String {
        self.profile.display_name()
    }

    pub fn connected(&self) -> bool {
        self.state == ConnState::Connected
    }

    /// Ainda tem worker vivo (conectando, aguardando chave ou conectada).
    pub fn alive(&self) -> bool {
        self.conn.is_some()
    }

    pub fn state_color(&self) -> Color32 {
        match self.state {
            ConnState::Connected => Color32::from_rgb(70, 200, 110),
            ConnState::Disconnected => Color32::GRAY,
            _ => Color32::from_rgb(230, 180, 60),
        }
    }

    /// Mensagem local exibida no terminal e no buffer de texto.
    pub fn echo(&mut self, msg: &str) {
        self.term.feed(msg);
        self.vterm.process(msg);
    }

    pub fn send(&self, msg: ToWorker) {
        if let Some(c) = &self.conn {
            c.send(msg);
        }
    }

    pub fn send_line(&self, cmd: &str) {
        self.send(ToWorker::Send(format!("{cmd}\r").into_bytes()));
    }

    pub fn disconnect(&self) {
        self.send(ToWorker::Disconnect);
    }

    /// Abre o arquivo de log da sessão; devolve o caminho.
    pub fn open_log(&mut self) -> Option<PathBuf> {
        let dir = logs_dir();
        fs::create_dir_all(&dir).ok()?;
        let safe: String = self
            .title()
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        // o id evita colisão entre sessões do mesmo perfil abertas no mesmo segundo
        let path = dir.join(format!(
            "{}_{}_{}.log",
            safe,
            chrono::Local::now().format("%Y%m%d_%H%M%S"),
            self.id
        ));
        let f = File::create(&path).ok()?;
        self.log = Some((BufWriter::new(f), path.clone()));
        Some(path)
    }

    pub fn close_log(&mut self) {
        if let Some((mut w, _)) = self.log.take() {
            let tail = self.term.lines.last().cloned().unwrap_or_default();
            let _ = writeln!(w, "{tail}");
            let _ = w.flush();
        }
    }

    /// Processa as mensagens do worker de conexão.
    pub fn poll(&mut self) -> Vec<SessionEvent> {
        self.poll_monitor();
        let mut out = Vec::new();
        let Some(conn) = &self.conn else { return out };
        let events: Vec<FromWorker> = conn.rx.try_iter().collect();
        for ev in events {
            match ev {
                FromWorker::Status(s) => {
                    self.status = s.clone();
                    out.push(SessionEvent::Status(s));
                }
                FromWorker::HostKeyPrompt { fingerprint, key_type } => {
                    self.status = "Confirme a chave do host".into();
                    self.state = ConnState::HostKey { fingerprint, key_type };
                }
                FromWorker::HostKeyAccepted { fingerprint } => {
                    out.push(SessionEvent::HostKeyAccepted {
                        host_key_id: self.profile.host_key_id(),
                        fingerprint,
                    });
                    self.state = ConnState::Connecting;
                }
                FromWorker::Connected => {
                    self.state = ConnState::Connected;
                    let p = &self.profile;
                    self.status = format!("Conectado ({}): {}:{}", p.protocol_label(), p.target(), p.port);
                    out.push(SessionEvent::Status(self.status.clone()));
                    out.push(SessionEvent::Connected);
                    self.focus_term = true;
                }
                FromWorker::Data(s) => {
                    if let Some(b) = &mut self.backup {
                        b.feed(&s);
                    }
                    self.vterm.process(&s);
                    let done = self.term.feed(&s);
                    if let Some((w, _)) = &mut self.log {
                        for l in done {
                            let _ = writeln!(w, "{l}");
                        }
                    }
                }
                FromWorker::Error(e) => {
                    let msg = format!("\r\n\x1b[31m[ERRO] {e}\x1b[0m\r\n")
                        .replace('\n', "\r\n")
                        .replace("\r\r\n", "\r\n");
                    self.echo(&msg);
                    out.push(SessionEvent::Error(e));
                }
                FromWorker::Closed => {
                    let backup_lost = self.backup.take().is_some();
                    self.echo("\r\n\x1b[36m===== conexão encerrada =====\x1b[0m\r\n");
                    self.state = ConnState::Disconnected;
                    self.status = "Desconectado".into();
                    self.close_log();
                    self.stop_monitor();
                    self.conn = None;
                    out.push(SessionEvent::Closed { backup_lost });
                    break;
                }
            }
        }
        out
    }
}
