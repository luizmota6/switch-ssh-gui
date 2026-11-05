//! Backup da configuração: captura a saída do comando (ex.: `show running-config`)
//! até o prompt da CLI voltar e grava em arquivo.

use crate::term::Terminal;
use std::time::{Duration, Instant};

/// Sem dados por este tempo, o backup é cancelado.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Backup {
    /// Terminal só para a captura (sem ANSI, com CR/backspace já tratados).
    term: Terminal,
    /// Linha do prompt no momento do disparo (ex.: "SW-LAB#").
    pub prompt: String,
    pub cmd: String,
    /// Paginação automática estava desligada no perfil e foi ligada para o backup.
    pub restore_pager_off: bool,
    pub last_data: Instant,
}

/// Linha parece um prompt de CLI de switch (Cisco/Aruba `#`/`>`, Comware `<x>`/`[x]`).
pub fn looks_like_prompt(line: &str) -> bool {
    let l = line.trim();
    !l.is_empty() && l.len() <= 80 && l.ends_with(['#', '>', ']'])
}

impl Backup {
    pub fn new(prompt: &str, cmd: &str, restore_pager_off: bool) -> Self {
        Self {
            term: Terminal::new(200_000),
            prompt: prompt.trim().to_string(),
            cmd: cmd.to_string(),
            restore_pager_off,
            last_data: Instant::now(),
        }
    }

    pub fn feed(&mut self, s: &str) {
        self.term.feed(s);
        self.last_data = Instant::now();
    }

    /// O prompt reapareceu depois de pelo menos uma linha de saída.
    pub fn done(&self) -> bool {
        self.term.lines.len() >= 2
            && self.term.lines.last().is_some_and(|l| l.trim() == self.prompt)
    }

    pub fn lines_captured(&self) -> usize {
        self.term.lines.len().saturating_sub(1)
    }

    pub fn result(&self) -> Result<String, String> {
        extract_config(&self.term.lines, &self.cmd)
    }
}

/// Remove o eco do comando e o prompt final; recusa respostas de erro da CLI.
pub fn extract_config(lines: &[String], cmd: &str) -> Result<String, String> {
    let mut body: &[String] = lines;
    // último elemento = prompt que voltou
    if let Some((_, rest)) = body.split_last() {
        body = rest;
    }
    // pula até a linha do eco do comando (pode vir com o prompt na frente)
    if let Some(i) = body.iter().position(|l| l.trim_end().ends_with(cmd)) {
        body = &body[i + 1..];
    }
    let start = body.iter().position(|l| !l.trim().is_empty()).unwrap_or(body.len());
    let end = body.iter().rposition(|l| !l.trim().is_empty()).map_or(start, |i| i + 1);
    let body = &body[start..end];

    let first = body.first().map(|l| l.trim().to_lowercase()).unwrap_or_default();
    let is_error = first.starts_with('%')
        || first.starts_with('^')
        || [
            "invalid input",
            "unrecognized command",
            "unknown command",
            "permission denied",
            // MikroTik
            "bad command name",
            "syntax error",
            "expected end of command",
            "not enough permissions",
            // Palo Alto
            "invalid syntax",
            "server error",
            // FortiGate
            "command parse error",
            "unknown action",
            "command fail",
        ]
        .iter()
        .any(|e| first.contains(e));
    if body.len() < 3 || is_error {
        return Err(format!(
            "O switch não devolveu a configuração{}.\n\
             Confira se o fabricante do perfil está certo e se o usuário tem privilégio \
             (no Cisco, entre com 'enable' antes).",
            if first.is_empty() { String::new() } else { format!(" (resposta: \"{}\")", body[0].trim()) }
        ));
    }
    let mut out = body.join("\r\n");
    out.push_str("\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn extrai_configuracao() {
        let lines = v(&[
            "SW-LAB# show running-config",
            "",
            "Running configuration:",
            "hostname \"SW-LAB\"",
            "vlan 1",
            "   name \"DEFAULT_VLAN\"",
            "",
            "SW-LAB# ",
        ]);
        let cfg = extract_config(&lines, "show running-config").unwrap();
        assert_eq!(
            cfg,
            "Running configuration:\r\nhostname \"SW-LAB\"\r\nvlan 1\r\n   name \"DEFAULT_VLAN\"\r\n"
        );
    }

    #[test]
    fn recusa_erro_da_cli() {
        let lines = v(&["SW> show running-config", "                 ^", "% Invalid input detected at '^' marker.", "SW>"]);
        assert!(extract_config(&lines, "show running-config").is_err());
    }

    #[test]
    fn mikrotik_e_palo_alto() {
        let rsc = v(&[
            "[admin@MikroTik] > /export",
            "# 2026-11-04 10:00:00 by RouterOS 7.16",
            "/interface bridge",
            "add name=bridge1",
            "[admin@MikroTik] > ",
        ]);
        let cfg = extract_config(&rsc, "/export").unwrap();
        assert!(cfg.starts_with("# 2026-11-04") && cfg.contains("add name=bridge1"));

        let pan = v(&["admin@PA-VM> show config running", "<config version=\"11.1.0\">", "  <devices/>", "</config>", "admin@PA-VM> "]);
        assert!(extract_config(&pan, "show config running").unwrap().starts_with("<config"));

        let erro = v(&["[leitura@MikroTik] > /export", "not enough permissions (9)", "", "[leitura@MikroTik] > "]);
        assert!(extract_config(&erro, "/export").is_err());
        let erro = v(&["admin@PA-VM> show config running", "Invalid syntax.", "x", "y", "admin@PA-VM> "]);
        assert!(extract_config(&erro, "show config running").is_err());
        assert!(looks_like_prompt("[admin@MikroTik] > ") && looks_like_prompt("admin@PA-VM> "));
    }

    #[test]
    fn detecta_fim_pelo_prompt() {
        let mut b = Backup::new("SW-LAB# ", "show running-config", false);
        b.feed("show running-config\r\nhostname x\r\n");
        assert!(!b.done());
        b.feed("vlan 1\r\nSW-LAB# ");
        assert!(b.done());
        assert!(looks_like_prompt("<HPE>") && looks_like_prompt("[HPE]") && looks_like_prompt("SW# "));
        assert!(!looks_like_prompt("Password:"));
    }
}
