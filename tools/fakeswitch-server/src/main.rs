//! Servidor SSH de teste que simula uma CLI Aruba AOS-CX — mesmo comportamento
//! de `tools/fakeswitch.py`, mas roda nativo no Windows (sem sshd/WSL/Python).
//!
//!   cargo run --release                 # escuta em 127.0.0.1:2222
//!   (na raiz do projeto) cargo test --release -- --ignored
//!
//! Login: sw / Teste@123 (senha ou keyboard-interactive).
//! Variáveis opcionais: FAKESWITCH_ADDR (padrão 127.0.0.1:2222).

use std::sync::Arc;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Response, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use tokio::net::TcpListener;

const USER: &str = "sw";
const PASS: &str = "Teste@123";
const PROMPT: &str = "\x1b[1mSWT-LAB#\x1b[0m ";
const MORE: &str = "-- MORE --, next page: Space, next line: Enter, quit: Control-C";

#[derive(Clone, Copy, PartialEq)]
enum State {
    /// Banner "Press any key to continue" — qualquer tecla segue.
    AnyKey,
    /// Lendo linha de comando.
    Line,
    /// Parado no "-- MORE --" — qualquer tecla continua, Ctrl+C aborta.
    More,
}

struct Shell {
    state: State,
    paging: bool,
    buf: String,
    /// Linhas ainda não enviadas do comando paginado atual.
    pending: Vec<String>,
}

impl Shell {
    fn new() -> Self {
        Shell { state: State::AnyKey, paging: true, buf: String::new(), pending: vec![] }
    }

    /// Processa os bytes recebidos e devolve a saída e se a sessão deve encerrar.
    fn feed(&mut self, data: &[u8]) -> (String, bool) {
        let mut out = String::new();
        for &b in data {
            match self.state {
                State::AnyKey => {
                    out.push_str("\r\x1b[2K");
                    out.push_str(PROMPT);
                    self.state = State::Line;
                }
                State::More => {
                    out.push_str("\r\x1b[2K");
                    if b == 0x03 {
                        self.pending.clear();
                    }
                    self.flush_page(&mut out);
                }
                State::Line => match b {
                    b'\r' | b'\n' => {
                        out.push_str("\r\n");
                        let cmd = std::mem::take(&mut self.buf);
                        if self.run(cmd.trim(), &mut out) {
                            return (out, true);
                        }
                    }
                    0x03 => {
                        self.buf.clear();
                        out.push_str("^C\r\n");
                        out.push_str(PROMPT);
                    }
                    0x7f | 0x08 => {
                        if self.buf.pop().is_some() {
                            out.push_str("\x08 \x08");
                        }
                    }
                    _ => {
                        let c = b as char;
                        self.buf.push(c);
                        out.push(c);
                    }
                },
            }
        }
        (out, false)
    }

    /// Executa um comando. Retorna `true` se for para encerrar a sessão.
    fn run(&mut self, cmd: &str, out: &mut String) -> bool {
        match cmd {
            "no page" => self.paging = false,
            "show version" => {
                out.push_str("ArubaOS-CX\r\nVersion : FL.10.13.1000\r\nUptime  : 12 days\r\n")
            }
            "show interface brief" => {
                self.pending = (1..=48)
                    .map(|i| format!("1/1/{i:<3} 1   access  up    1000  --"))
                    .collect();
                self.flush_page(out);
                return false; // flush_page cuida do prompt
            }
            "exit" | "logout" => {
                out.push_str("bye\r\n");
                return true;
            }
            "" => {}
            other => out.push_str(&format!("% Invalid input: {other}\r\n")),
        }
        out.push_str(PROMPT);
        false
    }

    /// Envia até 20 linhas (ou tudo, sem paginação). Para no "-- MORE --" se sobrar.
    fn flush_page(&mut self, out: &mut String) {
        let n = if self.paging { 20.min(self.pending.len()) } else { self.pending.len() };
        for l in self.pending.drain(..n) {
            out.push_str(&l);
            out.push_str("\r\n");
        }
        if self.pending.is_empty() {
            out.push_str(PROMPT);
            self.state = State::Line;
        } else {
            out.push_str(MORE);
            self.state = State::More;
        }
    }
}

struct Server;

impl server::Server for Server {
    type Handler = Handler;
    fn new_client(&mut self, addr: Option<std::net::SocketAddr>) -> Handler {
        println!("[+] conexão de {addr:?}");
        Handler { shell: Shell::new() }
    }
    fn handle_session_error(&mut self, e: <Handler as server::Handler>::Error) {
        eprintln!("[!] erro de sessão: {e:?}");
    }
}

struct Handler {
    shell: Shell,
}

fn methods() -> MethodSet {
    MethodSet::from(&[MethodKind::Password, MethodKind::KeyboardInteractive][..])
}

fn reject() -> Auth {
    Auth::Reject { proceed_with_methods: Some(methods()), partial_success: false }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let ok = user == USER && password == PASS;
        println!("[*] auth password user={user} -> {}", if ok { "OK" } else { "negado" });
        Ok(if ok { Auth::Accept } else { reject() })
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        match response {
            None => Ok(Auth::Partial {
                name: "".into(),
                instructions: "".into(),
                prompts: vec![("Password: ".into(), false)].into(),
            }),
            Some(mut r) => {
                let pass = r.next().map(|p| String::from_utf8_lossy(&p).into_owned());
                let ok = user == USER && pass.as_deref() == Some(PASS);
                println!("[*] auth keyboard-interactive user={user} -> {}", if ok { "OK" } else { "negado" });
                Ok(if ok { Auth::Accept } else { reject() })
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("[*] pty {term} {cols}x{rows}");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        _pw: u32,
        _ph: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        println!("[*] resize {cols}x{rows}");
        session.channel_success(channel)?;
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(
            channel,
            b"\x1b[2J\x1b[1;1HAruba AOS-CX (simulado)\r\nPress any key to continue".to_vec(),
        )?;
        Ok(())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let (out, quit) = self.shell.feed(data);
        if !out.is_empty() {
            session.data(channel, out.into_bytes())?;
        }
        if quit {
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)?;
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("FAKESWITCH_ADDR").unwrap_or_else(|_| "127.0.0.1:2222".into());
    let config = Arc::new(server::Config {
        auth_rejection_time: std::time::Duration::from_millis(300),
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        methods: methods(),
        keys: vec![PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let socket = TcpListener::bind(&addr).await.expect("não foi possível abrir a porta");
    println!("fakeswitch escutando em {addr} (usuário {USER} / {PASS}) — Ctrl+C para sair");
    Server.run_on_socket(config, &socket).await.unwrap();
}