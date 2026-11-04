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
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: AuthKind,
    pub key_path: String,
    pub vendor: Vendor,
    pub auto_pager: bool,
    /// Um comando por linha.
    pub custom_commands: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            protocol: Protocol::Ssh,
            host: String::new(),
            port: 22,
            user: "admin".into(),
            auth: AuthKind::Password,
            key_path: String::new(),
            vendor: Vendor::default(),
            auto_pager: true,
            custom_commands: String::new(),
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: Vec::new(),
            known_hosts: BTreeMap::new(),
            log_sessions: true,
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
