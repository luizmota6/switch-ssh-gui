//! Cofre: configuração + segredo do 2FA + senhas dos switches, cifrados com a senha mestra.
//!
//! Chave = Argon2id(senha mestra, sal aleatório). Dados = AES-256-GCM (nonce novo a cada
//! gravação; cabeçalho autenticado como AAD). Sem a senha mestra não há como ler nem
//! alterar o arquivo sem que a alteração seja detectada.

use crate::config::{vault_path, write_atomic, Config};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

const FORMAT: &str = "switch-ssh-gui-cofre";
const VERSION: u32 = 1;

/// Tamanho mínimo da senha mestra.
pub const MIN_PASSWORD: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Kdf {
    /// memória em KiB
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Kdf {
    fn default() -> Self {
        // ~64 MiB, 3 passadas: ~0,3–0,8 s por tentativa num PC comum
        #[cfg(not(test))]
        return Kdf { m: 64 * 1024, t: 3, p: 1 };
        #[cfg(test)]
        return Kdf { m: 1024, t: 1, p: 1 };
    }
}

/// Conteúdo cifrado.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultData {
    pub config: Config,
    pub totp_secret: Vec<u8>,
    /// Códigos de recuperação ainda não usados (normalizados, sem hífen).
    pub recovery_codes: Vec<String>,
    /// id do perfil -> senha do switch
    pub passwords: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    kdf: Kdf,
    salt: String,
    nonce: String,
    data: String,
}

/// Chave derivada mantida em memória enquanto o cofre está aberto.
pub struct Vault {
    key: [u8; 32],
    salt: [u8; 16],
    kdf: Kdf,
}

impl Drop for Vault {
    fn drop(&mut self) {
        // apaga a chave da memória (melhor esforço)
        for b in self.key.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

pub fn exists() -> bool {
    vault_path().exists()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("gerador aleatório do sistema indisponível");
    b
}

fn derive(password: &str, salt: &[u8], kdf: Kdf) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(kdf.m, kdf.t, kdf.p, Some(32)).map_err(|e| format!("Parâmetros do cofre inválidos: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Falha ao derivar a chave: {e}"))?;
    Ok(key)
}

fn aad(kdf: Kdf, salt_b64: &str) -> String {
    format!("{FORMAT}|{VERSION}|{}|{}|{}|{salt_b64}", kdf.m, kdf.t, kdf.p)
}

impl Vault {
    /// Cofre novo para a senha informada (ainda não grava nada).
    pub fn create(password: &str) -> Result<Self, String> {
        if password.chars().count() < MIN_PASSWORD {
            return Err(format!("A senha mestra precisa ter pelo menos {MIN_PASSWORD} caracteres."));
        }
        let salt = random::<16>();
        let kdf = Kdf::default();
        Ok(Self { key: derive(password, &salt, kdf)?, salt, kdf })
    }

    /// Abre o cofre gravado em disco.
    pub fn unlock(password: &str) -> Result<(Self, VaultData), String> {
        Self::unlock_bytes(
            &fs::read(vault_path()).map_err(|e| format!("Não foi possível ler o cofre: {e}"))?,
            password,
        )
    }

    fn unlock_bytes(raw: &[u8], password: &str) -> Result<(Self, VaultData), String> {
        let f: VaultFile = serde_json::from_slice(raw).map_err(|e| format!("Cofre corrompido: {e}"))?;
        if f.format != FORMAT || f.version != VERSION {
            return Err("Arquivo de cofre desconhecido ou de versão mais nova.".into());
        }
        let salt: [u8; 16] = B64
            .decode(&f.salt)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("Cofre corrompido (sal).")?;
        let nonce = B64.decode(&f.nonce).ok().filter(|n| n.len() == 12).ok_or("Cofre corrompido (nonce).")?;
        let data = B64.decode(&f.data).map_err(|_| "Cofre corrompido (dados).")?;
        let key = derive(password, &salt, f.kdf)?;
        let plain = Aes256Gcm::new(&key.into())
            .decrypt(Nonce::from_slice(&nonce), Payload { msg: &data, aad: aad(f.kdf, &f.salt).as_bytes() })
            .map_err(|_| "Senha mestra incorreta.".to_string())?;
        let vd: VaultData = serde_json::from_slice(&plain).map_err(|e| format!("Cofre corrompido: {e}"))?;
        Ok((Self { key, salt, kdf: f.kdf }, vd))
    }

    fn seal(&self, data: &VaultData) -> Result<Vec<u8>, String> {
        let plain = serde_json::to_vec(data).map_err(|e| e.to_string())?;
        let nonce = random::<12>();
        let salt_b64 = B64.encode(self.salt);
        let ct = Aes256Gcm::new(&self.key.into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plain, aad: aad(self.kdf, &salt_b64).as_bytes() })
            .map_err(|_| "Falha ao cifrar o cofre.".to_string())?;
        let f = VaultFile {
            format: FORMAT.into(),
            version: VERSION,
            kdf: self.kdf,
            salt: salt_b64,
            nonce: B64.encode(nonce),
            data: B64.encode(ct),
        };
        serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())
    }

    pub fn save(&self, data: &VaultData) -> Result<(), String> {
        write_atomic(&vault_path(), &self.seal(data)?)
    }

    /// Troca a senha mestra (sal e chave novos). Grave em seguida com `save`.
    pub fn change_password(&mut self, new_password: &str) -> Result<(), String> {
        *self = Self::create(new_password)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    fn sample() -> VaultData {
        let mut d = VaultData::default();
        d.config.profiles.push(Profile { id: "abc".into(), host: "10.0.0.1".into(), ..Default::default() });
        d.totp_secret = vec![1, 2, 3];
        d.passwords.insert("abc".into(), "Segredo@1".into());
        d
    }

    #[test]
    fn grava_e_abre() {
        let v = Vault::create("senha-forte").unwrap();
        let raw = v.seal(&sample()).unwrap();
        let txt = String::from_utf8_lossy(&raw);
        assert!(!txt.contains("Segredo@1") && !txt.contains("10.0.0.1"), "nada em texto puro");
        let (_, d) = Vault::unlock_bytes(&raw, "senha-forte").unwrap();
        assert_eq!(d.passwords["abc"], "Segredo@1");
        assert_eq!(d.config.profiles[0].host, "10.0.0.1");
    }

    #[test]
    fn senha_errada_e_adulteracao() {
        let v = Vault::create("senha-forte").unwrap();
        let raw = v.seal(&sample()).unwrap();
        assert_eq!(Vault::unlock_bytes(&raw, "senha-errada").err().unwrap(), "Senha mestra incorreta.");

        // trocar parâmetros do KDF no cabeçalho invalida a autenticação
        let mut f: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        f["kdf"]["t"] = 2.into();
        let raw2 = serde_json::to_vec(&f).unwrap();
        assert!(Vault::unlock_bytes(&raw2, "senha-forte").is_err());
    }

    #[test]
    fn senha_curta_recusada() {
        assert!(Vault::create("1234567").is_err());
    }

    #[test]
    fn trocar_senha() {
        let mut v = Vault::create("senha-antiga").unwrap();
        v.change_password("senha-nova-123").unwrap();
        let raw = v.seal(&sample()).unwrap();
        assert!(Vault::unlock_bytes(&raw, "senha-antiga").is_err());
        assert!(Vault::unlock_bytes(&raw, "senha-nova-123").is_ok());
    }
}
