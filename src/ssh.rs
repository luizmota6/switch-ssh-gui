//! Worker de conexão (SSH ou Telnet) em thread dedicada. A UI conversa com ele por canais mpsc.

use crate::config::Protocol;
use base64::Engine;
use ssh2::{HashType, KeyboardInteractivePrompt, Prompt, Session};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum Auth {
    Password(String),
    Key {
        path: PathBuf,
        passphrase: Option<String>,
    },
}

pub struct ConnectParams {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub known_fingerprint: Option<String>,
    pub auto_pager: bool,
    pub init_commands: Vec<String>,
    pub cols: u16,
    pub rows: u16,
}

pub enum ToWorker {
    Send(Vec<u8>),
    AcceptHostKey(bool),
    SetAutoPager(bool),
    Resize(u16, u16),
    Disconnect,
}

pub enum FromWorker {
    Status(String),
    HostKeyPrompt { fingerprint: String, key_type: String },
    HostKeyAccepted { fingerprint: String },
    Connected,
    Data(String),
    Error(String),
    Closed,
}

pub struct SshHandle {
    pub tx: Sender<ToWorker>,
    pub rx: Receiver<FromWorker>,
}

impl SshHandle {
    pub fn send(&self, msg: ToWorker) {
        let _ = self.tx.send(msg);
    }
}

pub fn spawn(params: ConnectParams, ctx: eframe::egui::Context) -> SshHandle {
    let (tx_cmd, rx_cmd) = mpsc::channel();
    let (tx_ev, rx_ev) = mpsc::channel();
    thread::Builder::new()
        .name("conn-worker".into())
        .spawn(move || {
            let emit = |ev: FromWorker| {
                let _ = tx_ev.send(ev);
                ctx.request_repaint();
            };
            let res = match params.protocol {
                Protocol::Ssh => run(params, &rx_cmd, &emit),
                Protocol::Telnet => crate::telnet::run(params, &rx_cmd, &emit),
            };
            if let Err(e) = res {
                emit(FromWorker::Error(e));
            }
            emit(FromWorker::Closed);
        })
        .expect("falha ao criar thread de conexão");
    SshHandle {
        tx: tx_cmd,
        rx: rx_ev,
    }
}

struct PasswordPrompter(String);

impl KeyboardInteractivePrompt for PasswordPrompter {
    fn prompt<'a>(&mut self, _u: &str, _i: &str, prompts: &[Prompt<'a>]) -> Vec<String> {
        prompts.iter().map(|_| self.0.clone()).collect()
    }
}

/// (marcador em minúsculas, tecla a enviar)
const PAGER_MARKERS: [(&str, &[u8]); 6] = [
    ("--more--", b" "),
    ("-- more --", b" "),
    ("---- more ----", b" "),
    ("press any key to continue", b" "),
    ("<--- more --->", b" "),
    // MikroTik RouterOS: "-- [Q quit|D dump|down]" -> D despeja o resto sem paginar
    ("[q quit|d dump|down]", b"d"),
];

/// Acumula o texto recebido em `tail` e, se apareceu um marcador de paginação,
/// devolve a tecla que o responde.
pub(crate) fn pager_hit(tail: &mut String, text: &str) -> Option<&'static [u8]> {
    tail.push_str(&text.to_lowercase());
    if tail.len() > 256 {
        let cut = tail.len() - 128;
        let cut = (cut..tail.len()).find(|&i| tail.is_char_boundary(i)).unwrap_or(0);
        tail.drain(..cut);
    }
    let reply = PAGER_MARKERS.iter().find(|(m, _)| tail.contains(m)).map(|(_, k)| *k);
    if reply.is_some() {
        tail.clear();
    }
    reply
}

/// Resolve o host e abre a conexão TCP (tenta todos os endereços).
pub(crate) fn connect_tcp(host: &str, port: u16, emit: &dyn Fn(FromWorker)) -> Result<TcpStream, String> {
    emit(FromWorker::Status(format!("Conectando a {host}:{port}…")));
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("Não foi possível resolver '{host}': {e}"))?
        .collect();
    let mut last_err = String::from("nenhum endereço");
    for a in &addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(8)) {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last_err = format!("{a}: {e}"),
        }
    }
    Err(format!("Falha TCP ({last_err})"))
}

/// Handshake SSH; devolve a sessão, o fingerprint SHA256 e o tipo da chave do host.
pub(crate) fn handshake(
    tcp: TcpStream,
    host: &str,
    port: u16,
    user: &str,
) -> Result<(Session, String, String), String> {
    let mut sess = Session::new().map_err(|e| e.to_string())?;
    sess.set_tcp_stream(tcp);
    sess.set_timeout(15_000);
    sess.handshake().map_err(|e| {
        format!(
            "Handshake SSH falhou: {e}\n\
             Sem algoritmo de criptografia em comum com o servidor. Diagnóstico:\n  \
             ssh -vv -p {port} {user}@{host}  (veja as linhas 'kex' e 'host key')"
        )
    })?;
    let fp_raw = sess
        .host_key_hash(HashType::Sha256)
        .ok_or("Servidor não apresentou chave de host")?;
    let fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(fp_raw)
    );
    let key_type = sess
        .host_key()
        .map(|(_, t)| format!("{t:?}"))
        .unwrap_or_else(|| "desconhecido".into());
    Ok((sess, fingerprint, key_type))
}

/// Compara o fingerprint recebido com o salvo (diferença = troca de chave ou MITM).
pub(crate) fn verify_known(known: &str, fingerprint: &str) -> Result<(), String> {
    if known == fingerprint {
        return Ok(());
    }
    Err(format!(
        "ALERTA DE SEGURANÇA: a chave do host mudou!\n  salva:    {known}\n  recebida: {fingerprint}\n\
         Pode ser troca de firmware/hardware — ou um ataque man-in-the-middle.\n\
         Se a mudança for legítima, remova a chave salva no perfil e conecte de novo."
    ))
}

/// Autentica por senha (password / keyboard-interactive) ou chave privada.
pub(crate) fn authenticate(sess: &Session, user: &str, auth: &Auth) -> Result<(), String> {
    let methods = sess.auth_methods(user).unwrap_or("").to_string();
    if !sess.authenticated() {
        match auth {
            Auth::Password(pw) => {
                if methods.is_empty() || methods.contains("password") {
                    let _ = sess.userauth_password(user, pw);
                }
                if !sess.authenticated() && methods.contains("keyboard-interactive") {
                    let mut pr = PasswordPrompter(pw.clone());
                    let _ = sess.userauth_keyboard_interactive(user, &mut pr);
                }
            }
            Auth::Key { path, passphrase } => {
                sess.userauth_pubkey_file(user, None, path, passphrase.as_deref())
                    .map_err(|e| format!("Falha na autenticação por chave: {e}"))?;
            }
        }
    }
    if !sess.authenticated() {
        return Err(format!(
            "Falha de autenticação (métodos aceitos pelo servidor: {})",
            if methods.is_empty() { "?" } else { &methods }
        ));
    }
    Ok(())
}

fn run(p: ConnectParams, rx: &Receiver<ToWorker>, emit: &dyn Fn(FromWorker)) -> Result<(), String> {
    // 1. TCP
    let tcp = connect_tcp(&p.host, p.port, emit)?;

    // 2. Handshake SSH
    let (sess, fingerprint, key_type) = handshake(tcp, &p.host, p.port, &p.user)?;

    // 3. Verificação da chave do host (TOFU)
    match &p.known_fingerprint {
        Some(known) => verify_known(known, &fingerprint)?,
        None => {
            emit(FromWorker::HostKeyPrompt {
                fingerprint: fingerprint.clone(),
                key_type,
            });
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(ToWorker::AcceptHostKey(true)) => break,
                    Ok(ToWorker::AcceptHostKey(false)) | Ok(ToWorker::Disconnect) => {
                        return Err("Chave do host rejeitada pelo usuário".into())
                    }
                    Ok(_) => continue,
                    Err(RecvTimeoutError::Timeout) => {
                        return Err("Tempo esgotado aguardando confirmação da chave".into())
                    }
                    Err(RecvTimeoutError::Disconnected) => return Ok(()),
                }
            }
            emit(FromWorker::HostKeyAccepted {
                fingerprint: fingerprint.clone(),
            });
        }
    }

    // 4. Autenticação
    emit(FromWorker::Status(if p.user.is_empty() {
        "Autenticando (sem usuário)…".to_string()
    } else {
        format!("Autenticando como {}…", p.user)
    }));
    authenticate(&sess, &p.user, &p.auth)?;

    // 5. Shell interativo com PTY
    let mut ch = sess
        .channel_session()
        .map_err(|e| format!("Falha ao abrir canal: {e}"))?;
    ch.request_pty("xterm-256color", None, Some((p.cols as u32, p.rows as u32, 0, 0)))
        .map_err(|e| format!("Falha ao requisitar PTY: {e}"))?;
    ch.shell().map_err(|e| format!("Falha ao abrir shell: {e}"))?;

    sess.set_keepalive(true, 30);
    sess.set_blocking(false);
    emit(FromWorker::Connected);

    // 6. Loop principal
    let mut auto_pager = p.auto_pager;
    let mut init: VecDeque<String> = p.init_commands.into();
    let mut got_data = false;
    let mut last_rx = Instant::now();
    let mut last_keepalive = Instant::now();
    let mut carry: Vec<u8> = Vec::new();
    let mut tail = String::new();
    let mut buf = [0u8; 16 * 1024];

    loop {
        let mut active = false;

        // leitura (drena até WouldBlock)
        loop {
            match ch.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    active = true;
                    got_data = true;
                    last_rx = Instant::now();
                    let text = decode_utf8(&mut carry, &buf[..n]);
                    if text.is_empty() {
                        continue;
                    }
                    if let Some(key) = auto_pager.then(|| pager_hit(&mut tail, &text)).flatten() {
                        write_nb(&mut ch, key)?;
                    }
                    emit(FromWorker::Data(text));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(format!("Erro de leitura: {e}")),
            }
        }

        if ch.eof() {
            emit(FromWorker::Status("Sessão encerrada pelo switch".into()));
            return Ok(());
        }

        // comandos de inicialização: após o banner e ~700 ms de silêncio
        if got_data && !init.is_empty() && last_rx.elapsed() > Duration::from_millis(700) {
            if let Some(cmd) = init.pop_front() {
                write_nb(&mut ch, format!("{cmd}\r").as_bytes())?;
                last_rx = Instant::now();
            }
        }

        // mensagens da UI
        loop {
            match rx.try_recv() {
                Ok(ToWorker::Send(bytes)) => {
                    active = true;
                    write_nb(&mut ch, &bytes)?;
                }
                Ok(ToWorker::SetAutoPager(v)) => auto_pager = v,
                Ok(ToWorker::Resize(c, r)) => {
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        match ch.request_pty_size(c as u32, r as u32, None, None) {
                            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) && Instant::now() < deadline => {
                                thread::sleep(Duration::from_millis(5))
                            }
                            _ => break,
                        }
                    }
                }
                Ok(ToWorker::AcceptHostKey(_)) => {}
                Ok(ToWorker::Disconnect) | Err(TryRecvError::Disconnected) => {
                    let _ = ch.send_eof();
                    let _ = ch.close();
                    let _ = sess.disconnect(None, "bye", None);
                    return Ok(());
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        if last_keepalive.elapsed() > Duration::from_secs(10) {
            let _ = sess.keepalive_send();
            last_keepalive = Instant::now();
        }

        if !active {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Escrita em sessão não-bloqueante, repetindo em WouldBlock.
fn write_nb(ch: &mut ssh2::Channel, mut data: &[u8]) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !data.is_empty() {
        match ch.write(data) {
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Err("Tempo esgotado ao enviar dados".into());
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("Erro de escrita: {e}")),
        }
    }
    loop {
        match ch.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() > deadline {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(format!("Erro de escrita: {e}")),
        }
    }
}

/// Decodifica UTF-8 preservando sequências multibyte cortadas entre leituras.
pub(crate) fn decode_utf8(carry: &mut Vec<u8>, new: &[u8]) -> String {
    carry.extend_from_slice(new);
    match std::str::from_utf8(carry) {
        Ok(s) => {
            let out = s.to_string();
            carry.clear();
            out
        }
        Err(e) if e.error_len().is_none() => {
            let valid = e.valid_up_to();
            let out = String::from_utf8_lossy(&carry[..valid]).into_owned();
            carry.drain(..valid);
            out
        }
        Err(_) => {
            let out = String::from_utf8_lossy(carry).into_owned();
            carry.clear();
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::Terminal;

    #[test]
    fn pager_responde_por_fabricante() {
        let mut t = String::new();
        assert_eq!(pager_hit(&mut t, "linha\r\n --More-- "), Some(&b" "[..]));
        assert_eq!(pager_hit(&mut t, "x\r\n-- [Q quit|D dump|down]"), Some(&b"d"[..]));
        assert_eq!(pager_hit(&mut t, "show lines 1-40"), None);
    }

    /// Integração contra sshd local (SSH_TEST_HOST=127.0.0.1:2222). Ignorado por padrão.
    #[test]
    #[ignore]
    fn end_to_end_fake_switch() {
        let ctx = eframe::egui::Context::default();
        let h = spawn(
            ConnectParams {
                protocol: Protocol::Ssh,
                host: "127.0.0.1".into(),
                port: 2222,
                user: "sw".into(),
                auth: Auth::Password("Teste@123".into()),
                known_fingerprint: None,
                auto_pager: true,
                init_commands: vec![],
                cols: 80,
                rows: 24,
            },
            ctx,
        );
        let mut t = Terminal::new(10_000);
        let start = Instant::now();
        let mut sent = false;
        while start.elapsed() < Duration::from_secs(15) {
            match h.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(FromWorker::HostKeyPrompt { fingerprint, .. }) => {
                    println!("FP {fingerprint}");
                    h.send(ToWorker::AcceptHostKey(true));
                }
                Ok(FromWorker::Connected) => println!("CONNECTED"),
                Ok(FromWorker::Data(s)) => { t.feed(&s); }
                Ok(FromWorker::Error(e)) => panic!("{e}"),
                Ok(FromWorker::Closed) => break,
                _ => {}
            }
            if !sent && t.text().contains("SWT-LAB#") {
                sent = true;
                h.send(ToWorker::Send(b"show version\rshow interface brief\r".to_vec()));
            }
            if t.text().contains("1/1/48") {
                h.send(ToWorker::Send(b"exit\r".to_vec()));
            }
        }
        let out = t.text();
        println!("{out}");
        assert!(out.contains("FL.10.13.1000"));
        assert!(out.contains("1/1/48"));
        assert!(!out.contains("MORE"));
    }
}
