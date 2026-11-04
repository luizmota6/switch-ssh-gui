//! Emulação mínima de terminal: remove sequências ANSI/VT100 e trata
//! CR, backspace e limpeza de linha — suficiente para CLIs de switch.

enum State {
    Normal,
    Esc,
    Csi(String),
    Osc,
    OscEsc,
}

pub struct Terminal {
    pub lines: Vec<String>,
    state: State,
    cr_pending: bool,
    max_lines: usize,
}

impl Terminal {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: vec![String::new()],
            state: State::Normal,
            cr_pending: false,
            max_lines,
        }
    }

    pub fn clear(&mut self) {
        self.lines = vec![String::new()];
        self.cr_pending = false;
        self.state = State::Normal;
    }

    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    fn cur(&mut self) -> &mut String {
        self.lines.last_mut().expect("sempre há uma linha")
    }

    fn newline(&mut self, done: &mut Vec<String>) {
        done.push(self.cur().clone());
        self.lines.push(String::new());
        self.cr_pending = false;
        if self.lines.len() > self.max_lines {
            let excess = self.lines.len() - self.max_lines;
            self.lines.drain(0..excess);
        }
    }

    fn csi(&mut self, params: &str, fin: char, done: &mut Vec<String>) {
        match fin {
            // Erase in line
            'K' => {
                if params == "2" || self.cr_pending {
                    self.cur().clear();
                    self.cr_pending = false;
                }
            }
            // Posicionamento de cursor: aproxima como quebra de linha
            'H' | 'f' | 'd' => {
                if !self.cur().is_empty() {
                    self.newline(done);
                }
            }
            // Clear screen: separa visualmente
            'J' if params == "2" => {
                if !self.cur().is_empty() {
                    self.newline(done);
                }
            }
            _ => {}
        }
    }

    /// Alimenta texto recebido; retorna as linhas que foram concluídas
    /// (para gravação de log).
    pub fn feed(&mut self, s: &str) -> Vec<String> {
        let mut done = Vec::new();
        for ch in s.chars() {
            match std::mem::replace(&mut self.state, State::Normal) {
                State::Esc => match ch {
                    '[' => self.state = State::Csi(String::new()),
                    ']' => self.state = State::Osc,
                    _ => {} // ESC + 1 caractere: ignora
                },
                State::Csi(mut p) => {
                    if ('\x40'..='\x7e').contains(&ch) {
                        self.csi(&p, ch, &mut done);
                    } else if p.len() < 32 {
                        p.push(ch);
                        self.state = State::Csi(p);
                    }
                }
                State::Osc => match ch {
                    '\x07' => {}
                    '\x1b' => self.state = State::OscEsc,
                    _ => self.state = State::Osc,
                },
                State::OscEsc => {
                    if ch != '\\' {
                        self.state = State::Osc;
                    }
                }
                State::Normal => match ch {
                    '\x1b' => self.state = State::Esc,
                    '\n' => self.newline(&mut done),
                    '\r' => self.cr_pending = true,
                    '\x08' | '\x7f' => {
                        self.cur().pop();
                    }
                    '\t' => {
                        let n = 8 - (self.cur().chars().count() % 8);
                        self.cur().push_str(&" ".repeat(n));
                    }
                    c if c.is_control() => {}
                    c => {
                        if self.cr_pending {
                            self.cur().clear();
                            self.cr_pending = false;
                        }
                        self.cur().push(c);
                    }
                },
            }
        }
        done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_and_handles_crlf() {
        let mut t = Terminal::new(100);
        t.feed("\x1b[1;32mswitch#\x1b[0m show ver\r\nline2\r\n");
        assert_eq!(t.lines, vec!["switch# show ver", "line2", ""]);
    }

    #[test]
    fn more_prompt_erased() {
        let mut t = Terminal::new(100);
        t.feed("a\r\n --More-- \x08\x08\x08\x08\x08\x08\x08\x08\x08\x08          \x08\x08\x08\x08\x08\x08\x08\x08\x08\x08b\r\n");
        assert_eq!(t.lines[1], "b");
    }

    #[test]
    fn cr_overwrites() {
        let mut t = Terminal::new(100);
        t.feed("-- MORE --\r\x1b[2Kport 1\r\n");
        assert_eq!(t.lines[0], "port 1");
    }
}
