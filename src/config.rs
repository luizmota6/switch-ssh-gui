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

/// Perfil de switch. A senha NUNCA é persistida.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub name: String,
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
            name: String::new(),
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
            format!("{}@{}", self.user, self.host)
        } else {
            self.name.clone()
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

pub fn logs_dir() -> PathBuf {
    dirs()
        .map(|d| d.data_dir().join("logs"))
        .unwrap_or_else(|| PathBuf::from("logs"))
}

impl Config {
    pub fn load() -> Self {
        fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        // grava atômico: tmp + rename
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &path).map_err(|e| e.to_string())
    }
}
