//! Cliente Telnet (RFC 854) com a mesma interface de eventos do worker SSH.
//!
//! Negocia ECHO/SGA (modo caractere), TTYPE (xterm-256color) e NAWS (tamanho da
//! janela). Se usuário/senha estiverem preenchidos, responde sozinho aos prompts
//! de login; senão o usuário digita direto no terminal.

use crate::ssh::{connect_tcp, decode_utf8, pager_hit, Auth, ConnectParams, FromWorker, ToWorker};
use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::{Duration, Instant};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;

const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;
const TERM_TYPE: &[u8] = b"XTERM-256COLOR";

#[derive(Clone, Copy)]
enum St {
    Data,
    Iac,
    Opt(u8),
    Sb,
    SbIac,
}

/// Máquina de estados do protocolo Telnet (independente de rede, testável).
pub struct Telnet {
    st: St,
    sb: Vec<u8>,
    /// Opções que nós (cliente) ativamos.
    local: [bool; 256],
    /// Opções que o servidor ativou.
    remote: [bool; 256],
    cols: u16,
    rows: u16,
}

impl Telnet {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            st: St::Data,
            sb: Vec::new(),
            local: [false; 256],
            remote: [false; 256],
            cols,
            rows,
        }
    }

    /// Ofertas iniciais (como PuTTY): servidor ecoa, sem go-ahead; informamos tipo e tamanho do terminal.
    pub fn greeting(&mut self) -> Vec<u8> {
        for opt in [OPT_ECHO, OPT_SGA] {
            self.remote[opt as usize] = true;
        }
        for opt in [OPT_SGA, OPT_TTYPE, OPT_NAWS] {
            self.local[opt as usize] = true;
        }
        vec![
            IAC, DO, OPT_ECHO, //
            IAC, DO, OPT_SGA, //
            IAC, WILL, OPT_SGA, //
            IAC, WILL, OPT_TTYPE, //
            IAC, WILL, OPT_NAWS,
        ]
    }

    /// Processa bytes recebidos: devolve os dados do terminal e acrescenta
    /// as respostas de negociação em `reply`.
    pub fn feed(&mut self, input: &[u8], reply: &mut Vec<u8>) -> Vec<u8> {
        let mut data = Vec::with_capacity(input.len());
        for &b in input {
            self.st = match self.st {
                St::Data => {
                    if b == IAC {
                        St::Iac
                    } else {
                        data.push(b);
                        St::Data
                    }
                }
                St::Iac => match b {
                    IAC => {
                        data.push(IAC);
                        St::Data
                    }
                    DO | DONT | WILL | WONT => St::Opt(b),
                    SB => {
                        self.sb.clear();
                        St::Sb
                    }
                    _ => St::Data, // NOP, GA, AYT etc.: ignorados
                },
                St::Opt(verb) => {
                    self.negotiate(verb, b, reply);
                    St::Data
                }
                St::Sb => {
                    if b == IAC {
                        St::SbIac
                    } else {
                        if self.sb.len() < 1024 {
                            self.sb.push(b);
                        }
                        St::Sb
                    }
                }
                St::SbIac => match b {
                    SE => {
                        self.subnegotiate(reply);
                        St::Data
                    }
                    IAC => {
                        self.sb.push(IAC);
                        St::Sb
                    }
                    _ => St::Data,
                },
            };
        }
        data
    }

    fn negotiate(&mut self, verb: u8, opt: u8, reply: &mut Vec<u8>) {
        let i = opt as usize;
        match verb {
            DO => {
                if matches!(opt, OPT_SGA | OPT_TTYPE | OPT_NAWS) {
                    if !self.local[i] {
                        self.local[i] = true;
                        reply.extend([IAC, WILL, opt]);
                    }
                    if opt == OPT_NAWS {
                        self.naws(reply);
                    }
                } else {
                    reply.extend([IAC, WONT, opt]);
                }
            }
            DONT => {
                if self.local[i] {
                    self.local[i] = false;
                    reply.extend([IAC, WONT, opt]);
                }
            }
            WILL => {
                if matches!(opt, OPT_ECHO | OPT_SGA) {
                    if !self.remote[i] {
                        self.remote[i] = true;
                        reply.extend([IAC, DO, opt]);
                    }
                } else {
                    reply.extend([IAC, DONT, opt]);
                }
            }
            WONT => {
                if self.remote[i] {
                    self.remote[i] = false;
                    reply.extend([IAC, DONT, opt]);
                }
            }
            _ => {}
        }
    }

    fn subnegotiate(&mut self, reply: &mut Vec<u8>) {
        if self.sb.as_slice() == [OPT_TTYPE, TTYPE_SEND] {
            reply.extend([IAC, SB, OPT_TTYPE, TTYPE_IS]);
            reply.extend_from_slice(TERM_TYPE);
            reply.extend([IAC, SE]);
        }
    }

    fn naws(&self, reply: &mut Vec<u8>) {
        reply.extend([IAC, SB, OPT_NAWS]);
        for b in self.cols.to_be_bytes().into_iter().chain(self.rows.to_be_bytes()) {
            reply.push(b);
            if b == IAC {
                reply.push(IAC);
            }
        }
        reply.extend([IAC, SE]);
    }

    /// Novo tamanho do terminal; envia NAWS se o servidor aceitou a opção.
    pub fn resize(&mut self, cols: u16, rows: u16, reply: &mut Vec<u8>) {
        self.cols = cols;
        self.rows = rows;
        if self.local[OPT_NAWS as usize] {
            self.naws(reply);
        }
    }
}

/// Codifica dados do teclado para a rede: dobra 0xFF e transforma CR isolado em CR NUL (NVT).
pub fn encode_out(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    for (i, &b) in data.iter().enumerate() {
        out.push(b);
        if b == IAC {
            out.push(IAC);
        } else if b == b'\r' && data.get(i + 1) != Some(&b'\n') {
            out.push(0);
        }
    }
    out
}

fn send(tcp: &mut TcpStream, bytes: &[u8]) -> Result<(), String> {
    tcp.write_all(bytes).map_err(|e| format!("Erro de escrita: {e}"))
}

fn ends_with_any(s: &str, pats: &[&str]) -> bool {
    pats.iter().any(|p| s.ends_with(p))
}

pub fn run(p: ConnectParams, rx: &Receiver<ToWorker>, emit: &dyn Fn(FromWorker)) -> Result<(), String> {
    let mut tcp = connect_tcp(&p.host, p.port, emit)?;
    // Timeout curto na leitura: o loop acorda a cada 10 ms para atender a UI.
    tcp.set_read_timeout(Some(Duration::from_millis(10)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    let mut tn = Telnet::new(p.cols, p.rows);
    let hello = tn.greeting();
    send(&mut tcp, &hello)?;
    emit(FromWorker::Connected);

    let password = match &p.auth {
        Auth::Password(pw) => pw.clone(),
        Auth::Key { .. } => String::new(),
    };
    let mut user_sent = p.user.is_empty();
    let mut pass_sent = password.is_empty();

    let mut auto_pager = p.auto_pager;
    let mut init: VecDeque<String> = p.init_commands.into();
    let mut at_prompt = false;
    let mut last_rx = Instant::now();
    let mut carry: Vec<u8> = Vec::new();
    let mut tail = String::new();
    let mut recent = String::new();
    let mut buf = [0u8; 16 * 1024];

    loop {
        match tcp.read(&mut buf) {
            Ok(0) => {
                emit(FromWorker::Status("Sessão encerrada pelo switch".into()));
                return Ok(());
            }
            Ok(n) => {
                let mut reply = Vec::new();
                let data = tn.feed(&buf[..n], &mut reply);
                if !reply.is_empty() {
                    send(&mut tcp, &reply)?;
                }
                let text = decode_utf8(&mut carry, &data);
                if !text.is_empty() {
                    last_rx = Instant::now();
                    if let Some(key) = auto_pager.then(|| pager_hit(&mut tail, &text)).flatten() {
                        send(&mut tcp, key)?;
                    }

                    // últimos caracteres (sem ANSI/NUL) para reconhecer prompts
                    recent.extend(text.to_lowercase().chars().filter(|c| *c != '\0'));
                    if recent.len() > 160 {
                        let cut = recent.len() - 80;
                        let cut = (cut..recent.len()).find(|&i| recent.is_char_boundary(i)).unwrap_or(0);
                        recent.drain(..cut);
                    }
                    let t = recent.trim_end();
                    if !user_sent && ends_with_any(t, &["login:", "username:", "user name:", "user:"]) {
                        user_sent = true;
                        recent.clear();
                        send(&mut tcp, &encode_out(format!("{}\r", p.user).as_bytes()))?;
                    } else if !pass_sent && t.ends_with("password:") {
                        pass_sent = true;
                        recent.clear();
                        send(&mut tcp, &encode_out(format!("{password}\r").as_bytes()))?;
                    }
                    let t = recent.trim_end();
                    at_prompt = ends_with_any(t, &["#", ">", "]"]);

                    emit(FromWorker::Data(text));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("Erro de leitura: {e}")),
        }

        // comandos de inicialização: só depois do login (prompt da CLI) e ~700 ms de silêncio
        if at_prompt && !init.is_empty() && last_rx.elapsed() > Duration::from_millis(700) {
            if let Some(cmd) = init.pop_front() {
                send(&mut tcp, &encode_out(format!("{cmd}\r").as_bytes()))?;
                at_prompt = false;
                last_rx = Instant::now();
            }
        }

        // mensagens da UI
        loop {
            match rx.try_recv() {
                Ok(ToWorker::Send(bytes)) => send(&mut tcp, &encode_out(&bytes))?,
                Ok(ToWorker::SetAutoPager(v)) => auto_pager = v,
                Ok(ToWorker::Resize(c, r)) => {
                    let mut reply = Vec::new();
                    tn.resize(c, r, &mut reply);
                    if !reply.is_empty() {
                        send(&mut tcp, &reply)?;
                    }
                }
                Ok(ToWorker::AcceptHostKey(_)) => {}
                Ok(ToWorker::Disconnect) | Err(TryRecvError::Disconnected) => {
                    let _ = tcp.shutdown(Shutdown::Both);
                    return Ok(());
                }
                Err(TryRecvError::Empty) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negocia_opcoes_e_extrai_dados() {
        let mut tn = Telnet::new(120, 40);
        let _ = tn.greeting();
        let mut reply = Vec::new();
        // servidor: WILL ECHO (já pedido -> sem resposta), DO NAWS (já oferecido -> só envia tamanho),
        // DO LINEMODE (34, recusado), texto com IAC IAC escapado
        let input = [
            IAC, WILL, OPT_ECHO, IAC, DO, OPT_NAWS, IAC, DO, 34, b'o', b'k', IAC, IAC, b'!',
        ];
        let data = tn.feed(&input, &mut reply);
        assert_eq!(data, vec![b'o', b'k', IAC, b'!']);
        assert_eq!(
            reply,
            vec![IAC, SB, OPT_NAWS, 0, 120, 0, 40, IAC, SE, IAC, WONT, 34]
        );
    }

    #[test]
    fn responde_tipo_de_terminal_mesmo_dividido_entre_leituras() {
        let mut tn = Telnet::new(80, 24);
        let mut reply = Vec::new();
        assert!(tn.feed(&[IAC, SB, OPT_TTYPE], &mut reply).is_empty());
        assert!(tn.feed(&[TTYPE_SEND, IAC, SE], &mut reply).is_empty());
        let mut expect = vec![IAC, SB, OPT_TTYPE, TTYPE_IS];
        expect.extend_from_slice(TERM_TYPE);
        expect.extend([IAC, SE]);
        assert_eq!(reply, expect);
    }

    #[test]
    fn codifica_saida() {
        assert_eq!(encode_out(b"show\r"), b"show\r\0".to_vec());
        assert_eq!(encode_out(b"a\r\nb"), b"a\r\nb".to_vec());
        assert_eq!(encode_out(&[1, IAC, 2]), vec![1, IAC, IAC, 2]);
    }

    /// Servidor Telnet falso em 127.0.0.1: pede usuário/senha, mostra prompt e pagina com --More--.
    #[test]
    fn login_automatico_paginacao_e_comando() {
        use crate::config::Protocol;
        use std::net::TcpListener;
        use std::sync::mpsc;

        type Rd = std::io::BufReader<TcpStream>;
        fn byte(r: &mut Rd) -> u8 {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).unwrap();
            b[0]
        }
        /// Próximo byte de dados, pulando negociação (IAC ...) e NUL/LF.
        fn next_data(r: &mut Rd) -> u8 {
            loop {
                match byte(r) {
                    IAC => match byte(r) {
                        SB => while !(byte(r) == IAC && byte(r) == SE) {},
                        IAC => return IAC,
                        _ => {
                            byte(r);
                        }
                    },
                    0 | b'\n' => {}
                    c => return c,
                }
            }
        }
        fn read_line(r: &mut Rd) -> Vec<u8> {
            let mut line = Vec::new();
            loop {
                match next_data(r) {
                    b'\r' => return line,
                    c => line.push(c),
                }
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut w = s.try_clone().unwrap();
            let mut r = std::io::BufReader::new(s);
            w.write_all(&[IAC, WILL, OPT_ECHO, IAC, DO, OPT_NAWS]).unwrap();
            w.write_all(b"\r\nUser Name: ").unwrap();
            let user = read_line(&mut r);
            w.write_all(b"\r\nPassword: ").unwrap();
            let pass = read_line(&mut r);
            w.write_all(b"\r\nSW-LAB# ").unwrap();
            let cmd = read_line(&mut r);
            w.write_all(b"\r\nlinha 1\r\n--More--").unwrap();
            let sp = next_data(&mut r);
            w.write_all(b"\r\nlinha 2\r\nSW-LAB# ").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            (user, pass, cmd, sp)
        });

        let (tx_cmd, rx_cmd) = mpsc::channel();
        let (tx_ev, rx_ev) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let emit = |ev: FromWorker| {
                let _ = tx_ev.send(ev);
            };
            run(
                ConnectParams {
                    protocol: Protocol::Telnet,
                    host: "127.0.0.1".into(),
                    port,
                    user: "admin".into(),
                    auth: Auth::Password("Teste@123".into()),
                    known_fingerprint: None,
                    auto_pager: true,
                    init_commands: vec!["no page".into()],
                    cols: 80,
                    rows: 24,
                },
                &rx_cmd,
                &emit,
            )
        });

        let mut out = String::new();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            match rx_ev.recv_timeout(Duration::from_millis(100)) {
                Ok(FromWorker::Data(s)) => out.push_str(&s),
                Ok(FromWorker::Error(e)) => panic!("{e}"),
                Ok(FromWorker::Closed) => break,
                _ => {}
            }
            if out.contains("linha 2") {
                break;
            }
        }
        let _ = tx_cmd.send(ToWorker::Disconnect);
        let (user, pass, cmd, space) = server.join().unwrap();
        worker.join().unwrap().unwrap();

        assert_eq!(user, b"admin");
        assert_eq!(pass, b"Teste@123");
        assert_eq!(cmd, b"no page", "comando de init enviado só depois do prompt");
        assert_eq!(space, b' ', "--More-- respondido com espaço");
        assert!(out.contains("linha 2"), "saída: {out}");
    }

    #[test]
    fn naws_escapa_255() {
        let mut tn = Telnet::new(80, 24);
        let _ = tn.greeting();
        let mut reply = Vec::new();
        tn.resize(255, 50, &mut reply);
        assert_eq!(reply, vec![IAC, SB, OPT_NAWS, 0, IAC, IAC, 0, 50, IAC, SE]);
    }
}
