//! TOTP (RFC 6238: HMAC-SHA1, 6 dígitos, 30 s) — compatível com Google/Microsoft
//! Authenticator, Authy, 1Password etc. Também gera códigos de recuperação.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ISSUER: &str = "SwitchSSHConsole";
const PERIOD: u64 = 30;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("gerador aleatório do sistema indisponível");
    b
}

/// Segredo novo de 160 bits (tamanho recomendado pela RFC 4226).
pub fn generate_secret() -> Vec<u8> {
    random_bytes::<20>().to_vec()
}

/// Segredo em Base32, agrupado de 4 em 4 para digitação manual no app.
pub fn secret_base32(secret: &[u8]) -> String {
    let s = data_encoding::BASE32_NOPAD.encode(secret);
    s.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
}

/// URL `otpauth://` que vai no QR code.
pub fn otpauth_url(secret: &[u8], account: &str) -> String {
    let enc = |s: &str| -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    };
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period={PERIOD}",
        issuer = enc(ISSUER),
        account = enc(account),
        secret = data_encoding::BASE32_NOPAD.encode(secret),
    )
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC aceita qualquer tamanho de chave");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(digits)
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Confere um código de 6 dígitos aceitando ±1 janela (relógio do celular adiantado/atrasado ~30 s).
pub fn verify(secret: &[u8], code: &str, unix_time: u64) -> bool {
    let digits: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Ok(n) = digits.parse::<u32>() else { return false };
    let step = unix_time / PERIOD;
    // compara todas as janelas sem sair cedo
    [step.saturating_sub(1), step, step + 1]
        .iter()
        .fold(false, |ok, &s| ok | (hotp(secret, s, 6) == n))
}

/// Alfabeto sem caracteres ambíguos (0/O, 1/I/L).
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// `n` códigos de uso único no formato XXXXX-XXXXX.
pub fn recovery_codes(n: usize) -> Vec<String> {
    (0..n)
        .map(|_| {
            let r = random_bytes::<10>();
            let s: String = r.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect();
            format!("{}-{}", &s[..5], &s[5..])
        })
        .collect()
}

/// Normaliza o que o usuário digitou (maiúsculas, sem espaço/hífen) para comparar códigos de recuperação.
pub fn normalize_recovery(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vetores da RFC 6238 (SHA1, segredo "12345678901234567890"), 8 dígitos.
    #[test]
    fn vetores_rfc6238() {
        let k = b"12345678901234567890";
        for (t, expect) in [
            (59u64, 94287082u32),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
        ] {
            assert_eq!(hotp(k, t / 30, 8), expect, "t={t}");
        }
    }

    #[test]
    fn verifica_com_tolerancia_de_janela() {
        let k = b"12345678901234567890";
        let code = format!("{:06}", hotp(k, 1111111109 / 30, 6)); // 081804
        assert_eq!(code, "081804");
        assert!(verify(k, "081 804", 1111111109));
        assert!(verify(k, &code, 1111111109 + 30)); // uma janela depois
        assert!(!verify(k, &code, 1111111109 + 90)); // longe demais
        assert!(!verify(k, "12345", 1111111109));
        assert!(!verify(k, "abcdef", 1111111109));
    }

    #[test]
    fn url_e_codigos() {
        let url = otpauth_url(b"12345678901234567890", "luiz pc");
        assert!(url.starts_with("otpauth://totp/SwitchSSHConsole:luiz%20pc?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"));
        let codes = recovery_codes(10);
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|c| c.len() == 11 && c.as_bytes()[5] == b'-'));
        assert_eq!(normalize_recovery("abcde-fghjk "), "ABCDEFGHJK");
    }
}
