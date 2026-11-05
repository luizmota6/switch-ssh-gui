use crate::vendor::Vendor;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthKind {
    #[default]
    Password,
    Key,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Protocol {
    #[default]
    Ssh,
    Telnet,
}

impl Protocol {
    pub fn label(self) -> &'static str {
        match self {
            Protocol::Ssh => "SSH",
            Protocol::Telnet => "Telnet",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh => 22,
            Protocol::Telnet => 23,
        }
    }
}

/// Perfil de switch. A senha NUNCA é persistida.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// Identificador estável (chave da senha salva no cofre).
    pub id: String,
    pub name: String,
    /// `None` = ainda não escolhido (obrigatório antes de conectar).
    pub protocol: Option<Protocol>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthKind,
    pub key_path: String,
    /// `None` = ainda não escolhido (obrigatório antes de conectar).
    pub vendor: Option<Vendor>,
    pub auto_pager: bool,
    /// Um comando por linha.
    pub custom_commands: String,
    /// Executa os comandos personalizados automaticamente após o login.
    pub run_custom_on_login: bool,
    /// SSH: mostra CPU/memória/disco/rede/uptime do servidor (Linux) em tempo real.
    pub monitor_resources: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: None,
            host: String::new(),
            port: 22,
            user: "admin".into(),
            auth: AuthKind::Password,
            key_path: String::new(),
            vendor: None,
            auto_pager: true,
            custom_commands: String::new(),
            run_custom_on_login: false,
            monitor_resources: true,
        }
    }
}

impl Profile {
    pub fn display_name(&self) -> String {
        if self.name.trim().is_empty() {
            self.target()
        } else {
            self.name.clone()
        }
    }

    /// "usuário@host", ou só "host" quando o usuário está em branco.
    pub fn target(&self) -> String {
        let user = self.user.trim();
        if user.is_empty() {
            self.host.trim().to_string()
        } else {
            format!("{user}@{}", self.host.trim())
        }
    }

    pub fn is_telnet(&self) -> bool {
        self.protocol == Some(Protocol::Telnet)
    }

    pub fn is_ssh(&self) -> bool {
        self.protocol == Some(Protocol::Ssh)
    }

    pub fn protocol_label(&self) -> &'static str {
        self.protocol.map_or("protocolo?", Protocol::label)
    }

    pub fn vendor_label(&self) -> &'static str {
        self.vendor.map_or("Fabricante não definido", Vendor::label)
    }

    /// Fabricante escolhido, ou Genérico (sem comandos específicos) se não definido.
    pub fn vendor_or_generic(&self) -> Vendor {
        self.vendor.unwrap_or(Vendor::Generico)
    }

    /// O que falta escolher antes de conectar (None = tudo definido).
    pub fn missing_choice(&self) -> Option<&'static str> {
        match (self.vendor, self.protocol) {
            (None, None) => Some("Escolha o fabricante e o protocolo (SSH/Telnet) do switch antes de conectar."),
            (None, _) => Some("Escolha o fabricante do switch antes de conectar."),
            (_, None) => Some("Escolha o protocolo (SSH ou Telnet) antes de conectar."),
            _ => None,
        }
    }

    /// Porta é a padrão do *outro* protocolo (ex.: SSH na 23) — provável engano.
    pub fn port_mismatch(&self) -> Option<String> {
        let p = self.protocol?;
        let other = match p {
            Protocol::Ssh => Protocol::Telnet,
            Protocol::Telnet => Protocol::Ssh,
        };
        (self.port == other.default_port()).then(|| {
            format!(
                "A porta {} é a padrão do {}, mas o protocolo escolhido é {}.",
                self.port,
                other.label(),
                p.label()
            )
        })
    }

    /// Comandos enviados após o login: os do fabricante e, se ativado, os personalizados.
    /// Devolve (a enviar, personalizados perigosos que foram ignorados).
    pub fn login_commands(&self) -> (Vec<String>, Vec<String>) {
        let mut send: Vec<String> = self
            .vendor_or_generic()
            .init_commands()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut skipped = Vec::new();
        if self.run_custom_on_login {
            for c in self.custom_list() {
                if crate::vendor::is_dangerous(&c) {
                    skipped.push(c);
                } else {
                    send.push(c);
                }
            }
        }
        (send, skipped)
    }

    pub fn host_key_id(&self) -> String {
        format!("{}:{}", self.host.trim().to_lowercase(), self.port)
    }

    pub fn custom_list(&self) -> Vec<String> {
        self.custom_commands
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub profiles: Vec<Profile>,
    /// "host:porta" -> "SHA256:base64"
    pub known_hosts: BTreeMap<String, String>,
    pub log_sessions: bool,
    /// Protetor de tela (Matrix) após N minutos sem uso; 0 = desligado.
    pub screensaver_minutes: u32,
    /// Estilo do protetor de tela.
    pub screensaver_style: ScreensaverStyle,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            known_hosts: BTreeMap::new(),
            log_sessions: true,
            screensaver_minutes: 5,
            screensaver_style: ScreensaverStyle::Matrix,
        }
    }
}

fn dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "switch-ssh-gui")
}

pub fn config_path() -> PathBuf {
    dirs()
        .map(|d| d.config_dir().join("config.json"))
        .unwrap_or_else(|| PathBuf::from("switch-ssh-gui.json"))
}

/// Arquivo do cofre criptografado (substitui o config.json quando a senha mestra está ativa).
pub fn vault_path() -> PathBuf {
    config_path().with_file_name("cofre.json")
}

/// Identificador aleatório (hex) para perfis.
pub fn new_id() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn backups_dir() -> PathBuf {
    dirs()
        .map(|d| d.data_dir().join("backups"))
        .unwrap_or_else(|| PathBuf::from("backups"))
}

pub fn logs_dir() -> PathBuf {
    dirs()
        .map(|d| d.data_dir().join("logs"))
        .unwrap_or_else(|| PathBuf::from("logs"))
}

impl Config {
    /// Garante que todo perfil tem id (perfis antigos não tinham).
    pub fn ensure_ids(&mut self) {
        for p in &mut self.profiles {
            if p.id.is_empty() {
                p.id = new_id();
            }
        }
    }

    pub fn load() -> Self {
        fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&config_path(), json.as_bytes())
    }
}

/// Grava atômico: tmp + rename (nunca deixa o arquivo pela metade).
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, data).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perfil_salvo_mantem_fabricante_e_protocolo() {
        let p: Profile = serde_json::from_str(
            r#"{"name":"core","protocol":"Telnet","host":"10.0.0.1","port":23,"vendor":"CiscoIos"}"#,
        )
        .unwrap();
        assert_eq!(p.vendor, Some(Vendor::CiscoIos));
        assert_eq!(p.protocol, Some(Protocol::Telnet));
        assert!(p.missing_choice().is_none());
        assert!(p.port_mismatch().is_none());
    }

    #[test]
    fn perfil_novo_ou_antigo_sem_campos_exige_escolha() {
        assert!(Profile::default().missing_choice().is_some());
        let p: Profile = serde_json::from_str(r#"{"host":"10.0.0.1"}"#).unwrap();
        assert!(p.vendor.is_none() && p.protocol.is_none());
        assert!(p.missing_choice().is_some());
    }

    #[test]
    fn porta_de_outro_protocolo_gera_alerta() {
        let p = Profile { protocol: Some(Protocol::Ssh), port: 23, ..Profile::default() };
        assert!(p.port_mismatch().is_some());
    }
}

#[cfg(test)]
mod login_tests {
    use super::*;

    #[test]
    fn personalizados_apos_login() {
        let mut p = Profile {
            vendor: Some(Vendor::CiscoIos),
            custom_commands: "show clock\n# comentário\nreload\nshow ip int brief".into(),
            ..Profile::default()
        };
        // desligado: só os do fabricante
        assert_eq!(p.login_commands().0, vec!["terminal length 0", "terminal width 0"]);
        p.run_custom_on_login = true;
        let (send, skipped) = p.login_commands();
        assert_eq!(
            send,
            vec!["terminal length 0", "terminal width 0", "show clock", "show ip int brief"]
        );
        assert_eq!(skipped, vec!["reload"]);
    }
}

/// Estilo do protetor de tela.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ScreensaverStyle {
    /// Chuva digital verde.
    #[default]
    Matrix,
    /// Pinguins que caem de guarda-chuva, andam e escalam a interface.
    Pinguins,
}

impl ScreensaverStyle {
    pub const ALL: [ScreensaverStyle; 2] = [ScreensaverStyle::Matrix, ScreensaverStyle::Pinguins];

    pub fn label(self) -> &'static str {
        match self {
            ScreensaverStyle::Matrix => "Matrix",
            ScreensaverStyle::Pinguins => "Pinguins",
        }
    }
}
