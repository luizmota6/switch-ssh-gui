//! Telas de segurança: desbloqueio (senha mestra + 2FA), ativação, troca de senha,
//! códigos de recuperação e desativação do cofre.

use super::{ConnState, SwitchApp};
use crate::config::{config_path, vault_path, Config, Profile};
use crate::totp;
use crate::vault::{Vault, VaultData, MIN_PASSWORD};
use eframe::egui::{self, Color32, RichText};
use std::collections::BTreeMap;
use std::fs;
use std::time::{Duration, Instant};

const RED: Color32 = Color32::from_rgb(240, 90, 90);
const GREEN: Color32 = Color32::from_rgb(70, 200, 110);
const ORANGE: Color32 = Color32::from_rgb(230, 180, 60);

/// Cofre aberto: chave derivada + dados que não fazem parte do `Config`.
pub struct VaultSession {
    vault: Vault,
    totp_secret: Vec<u8>,
    /// códigos de recuperação restantes (normalizados)
    recovery: Vec<String>,
    /// id do perfil -> senha do switch
    pub passwords: BTreeMap<String, String>,
}

impl VaultSession {
    pub fn save(&self, cfg: &Config) -> Result<(), String> {
        self.vault.save(&VaultData {
            config: cfg.clone(),
            totp_secret: self.totp_secret.clone(),
            recovery_codes: self.recovery.clone(),
            passwords: self.passwords.clone(),
        })
    }
}

#[derive(Default)]
pub struct LockScreen {
    password: String,
    code: String,
    error: Option<String>,
    fails: u32,
    wait_until: Option<Instant>,
    focused: bool,
}

#[derive(Default)]
pub struct Setup {
    step: u8,
    pw1: String,
    pw2: String,
    secret: Vec<u8>,
    code: String,
    recovery: Vec<String>,
    saved: bool,
    error: Option<String>,
}

pub enum SecurityDialog {
    Menu,
    Setup(Setup),
    ChangePassword { current: String, new1: String, new2: String, error: Option<String> },
    Disable { password: String, code: String, error: Option<String> },
    Recovery(Vec<String>),
}

impl SecurityDialog {
    pub fn menu() -> Self {
        SecurityDialog::Menu
    }
}

enum Act {
    None,
    Close,
    Goto(SecurityDialog),
    FinishSetup,
    ChangePassword,
    Disable,
    NewRecovery,
}

/// Confere o 2º fator: código TOTP ou um código de recuperação (que é consumido).
/// `Some(true)` = entrou com código de recuperação.
fn second_factor(secret: &[u8], recovery: &mut Vec<String>, input: &str) -> Option<bool> {
    if totp::verify(secret, input, totp::now()) {
        return Some(false);
    }
    let n = totp::normalize_recovery(input);
    if n.len() == 10 {
        if let Some(i) = recovery.iter().position(|c| *c == n) {
            recovery.remove(i);
            return Some(true);
        }
    }
    None
}

fn account_name() -> String {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "usuario".into());
    match std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")) {
        Ok(host) => format!("{user}@{host}"),
        Err(_) => user,
    }
}

fn draw_qr(ui: &mut egui::Ui, data: &str) {
    let Ok(code) = qrcode::QrCode::new(data.as_bytes()) else {
        ui.colored_label(RED, "Não foi possível gerar o QR code; use a chave manual abaixo.");
        return;
    };
    let w = code.width();
    let colors = code.to_colors();
    let quiet = 4usize;
    let scale = 5.0;
    let size = (w + 2 * quiet) as f32 * scale;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, Color32::WHITE);
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                let min = rect.min + egui::vec2((x + quiet) as f32 * scale, (y + quiet) as f32 * scale);
                painter.rect_filled(egui::Rect::from_min_size(min, egui::vec2(scale, scale)), 0.0, Color32::BLACK);
            }
        }
    }
}

fn recovery_list(ui: &mut egui::Ui, codes: &[String]) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        egui::Grid::new("recovery").num_columns(2).spacing([24.0, 4.0]).show(ui, |ui| {
            for pair in codes.chunks(2) {
                for c in pair {
                    ui.label(RichText::new(c).monospace().size(15.0));
                }
                ui.end_row();
            }
        });
    });
    if ui.button("📋 Copiar códigos").clicked() {
        ui.ctx().copy_text(codes.join("\r\n"));
    }
}

fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    ui.label(label);
    let r = ui.add(egui::TextEdit::singleline(value).password(true).desired_width(240.0));
    ui.end_row();
    r
}

fn error_label(ui: &mut egui::Ui, error: &Option<String>) {
    if let Some(e) = error {
        ui.add_space(4.0);
        ui.colored_label(RED, e);
    }
}

fn setup_ui(ui: &mut egui::Ui, s: &mut Setup, act: &mut Act) {
    match s.step {
        0 | 1 => {
            ui.label(RichText::new("Passo 1 de 3 — senha mestra").strong());
            ui.label(format!(
                "Mínimo {MIN_PASSWORD} caracteres. Ela não pode ser recuperada: guarde num gerenciador de senhas."
            ));
            ui.add_space(6.0);
            egui::Grid::new("setup1").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                password_field(ui, "Senha mestra", &mut s.pw1);
                password_field(ui, "Repita a senha", &mut s.pw2);
            });
            ui.add_space(6.0);
            if ui.button("Avançar ➡").clicked() {
                if s.pw1.chars().count() < MIN_PASSWORD {
                    s.error = Some(format!("A senha precisa ter pelo menos {MIN_PASSWORD} caracteres."));
                } else if s.pw1 != s.pw2 {
                    s.error = Some("As senhas não conferem.".into());
                } else {
                    if s.secret.is_empty() {
                        s.secret = totp::generate_secret();
                    }
                    s.step = 2;
                    s.error = None;
                }
            }
        }
        2 => {
            ui.label(RichText::new("Passo 2 de 3 — cadastre no app autenticador").strong());
            ui.label("Escaneie com o Google Authenticator, Microsoft Authenticator, Authy etc.:");
            ui.add_space(4.0);
            draw_qr(ui, &totp::otpauth_url(&s.secret, &account_name()));
            ui.add_space(4.0);
            ui.label("Ou digite a chave manualmente (tipo: baseado em tempo):");
            ui.add(egui::Label::new(RichText::new(totp::secret_base32(&s.secret)).monospace().strong()).selectable(true));
            ui.add_space(8.0);
            ui.label("Código de 6 dígitos que aparece no app:");
            let r = ui.add(egui::TextEdit::singleline(&mut s.code).desired_width(120.0).hint_text("000000"));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            ui.horizontal(|ui| {
                if ui.button("⬅ Voltar").clicked() {
                    s.step = 1;
                    s.error = None;
                }
                if ui.button("Verificar ➡").clicked() || enter {
                    if totp::verify(&s.secret, &s.code, totp::now()) {
                        s.recovery = totp::recovery_codes(10);
                        s.step = 3;
                        s.error = None;
                    } else {
                        s.error = Some(
                            "Código inválido. Confira se a data/hora do celular e do PC estão certas (automáticas).".into(),
                        );
                    }
                }
            });
        }
        _ => {
            ui.label(RichText::new("Passo 3 de 3 — códigos de recuperação").strong());
            ui.label(
                "Se perder o celular, use um destes no lugar do código do autenticador. \
                 Cada código vale uma vez. Guarde fora deste computador.",
            );
            ui.add_space(4.0);
            recovery_list(ui, &s.recovery);
            ui.add_space(6.0);
            ui.checkbox(&mut s.saved, "Guardei os códigos em local seguro");
            if ui
                .add_enabled(s.saved, egui::Button::new(RichText::new("✔ Concluir e ativar").strong()))
                .clicked()
            {
                *act = Act::FinishSetup;
            }
        }
    }
    error_label(ui, &s.error);
}

impl SwitchApp {
    // ---------- tela de desbloqueio ----------

    pub(super) fn ui_lock_screen(&mut self, ctx: &egui::Context) {
        let Some(mut ls) = self.locked.take() else { return };
        let waiting = ls
            .wait_until
            .map(|t| t.saturating_duration_since(Instant::now()))
            .filter(|d| !d.is_zero());
        if waiting.is_some() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        let mut submit = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() * 0.15);
                ui.heading(RichText::new("🔒 Switch SSH Console").size(26.0));
                ui.label("Protegido por senha mestra e autenticação em dois fatores.");
                ui.add_space(18.0);
                ui.label("Senha mestra");
                let r1 = ui.add_sized([280.0, 24.0], egui::TextEdit::singleline(&mut ls.password).password(true));
                if !ls.focused {
                    r1.request_focus();
                    ls.focused = true;
                }
                ui.add_space(8.0);
                ui.label("Código do autenticador (ou código de recuperação)");
                let r2 = ui.add_sized([280.0, 24.0], egui::TextEdit::singleline(&mut ls.code).hint_text("000000"));
                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if r1.lost_focus() && enter && ls.code.is_empty() {
                    r2.request_focus();
                } else if (r1.lost_focus() || r2.lost_focus()) && enter {
                    submit = true;
                }
                ui.add_space(12.0);
                let btn = ui.add_enabled(
                    waiting.is_none(),
                    egui::Button::new(RichText::new("Desbloquear").strong()).min_size(egui::vec2(280.0, 30.0)),
                );
                submit = waiting.is_none() && (submit || btn.clicked());
                if let Some(w) = waiting {
                    ui.colored_label(ORANGE, format!("Muitas tentativas. Aguarde {} s.", w.as_secs() + 1));
                }
                error_label(ui, &ls.error);
                ui.add_space(40.0);
                ui.weak(format!(
                    "Esqueceu a senha mestra? Ela não pode ser recuperada.\n\
                     Para recomeçar do zero, apague o arquivo\n{}\n(os perfis e senhas guardados nele serão perdidos).",
                    vault_path().display()
                ));
            });
        });
        if !(submit && self.try_unlock(&mut ls)) {
            self.locked = Some(ls);
        }
    }

    fn try_unlock(&mut self, ls: &mut LockScreen) -> bool {
        match Vault::unlock(&ls.password) {
            Ok((vault, data)) => {
                let VaultData { config, totp_secret, mut recovery_codes, passwords } = data;
                if let Some(used_recovery) = second_factor(&totp_secret, &mut recovery_codes, &ls.code) {
                    let left = recovery_codes.len();
                    self.vault = Some(VaultSession { vault, totp_secret, recovery: recovery_codes, passwords });
                    self.cfg = config;
                    self.after_config_loaded();
                    self.status = "Cofre desbloqueado".into();
                    if used_recovery {
                        self.save_cfg(); // consome o código de recuperação
                        self.error = Some(format!(
                            "Você entrou com um código de recuperação (restam {left}). \
                             Gere novos códigos em 🔒 Segurança."
                        ));
                    }
                    return true;
                }
            }
            Err(e) if e != "Senha mestra incorreta." => {
                ls.error = Some(e);
                return false;
            }
            Err(_) => {}
        }
        ls.fails += 1;
        ls.code.clear();
        ls.error = Some("Senha mestra ou código inválido.".into());
        if ls.fails >= 3 {
            let secs = (5u64 << (ls.fails - 3).min(6)).min(300);
            ls.wait_until = Some(Instant::now() + Duration::from_secs(secs));
        }
        false
    }

    /// Fecha o cofre: derruba a sessão e apaga da memória perfis, senhas e a saída do terminal.
    pub(super) fn lock(&mut self) {
        if let Some(c) = self.conn.take() {
            c.send(crate::ssh::ToWorker::Disconnect);
        }
        self.close_log();
        self.state = ConnState::Disconnected;
        self.session_profile = None;
        self.backup = None;
        self.vault = None;
        self.cfg = Config::default();
        self.selected = None;
        self.select_form(Profile::default());
        self.term.clear();
        self.vterm.clear();
        self.input.clear();
        self.history.clear();
        self.confirm = None;
        self.security = None;
        self.error = None;
        self.status = "Bloqueado".into();
        self.locked = Some(LockScreen::default());
    }

    // ---------- janela "Segurança" ----------

    pub(super) fn ui_security(&mut self, ctx: &egui::Context) {
        let Some(mut dlg) = self.security.take() else { return };
        let has_vault = self.vault.is_some();
        let left = self.vault.as_ref().map_or(0, |v| v.recovery.len());
        let mut open = true;
        let mut act = Act::None;
        egui::Window::new("🔒 Segurança")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(470.0);
                match &mut dlg {
                    SecurityDialog::Menu if has_vault => {
                        ui.label(RichText::new("✔ Senha mestra e 2FA ativos").strong().color(GREEN));
                        ui.label("Perfis, chaves de host e senhas salvas ficam cifrados (Argon2id + AES-256-GCM).");
                        let color = if left <= 2 { ORANGE } else { ui.visuals().text_color() };
                        ui.colored_label(color, format!("Códigos de recuperação restantes: {left}"));
                        ui.add_space(8.0);
                        if ui.button("Trocar senha mestra").clicked() {
                            act = Act::Goto(SecurityDialog::ChangePassword {
                                current: String::new(),
                                new1: String::new(),
                                new2: String::new(),
                                error: None,
                            });
                        }
                        if ui.button("Gerar novos códigos de recuperação").clicked() {
                            act = Act::NewRecovery;
                        }
                        if ui.button("Desativar senha mestra e 2FA").clicked() {
                            act = Act::Goto(SecurityDialog::Disable {
                                password: String::new(),
                                code: String::new(),
                                error: None,
                            });
                        }
                    }
                    SecurityDialog::Menu => {
                        ui.label(
                            "Exija senha mestra + código do autenticador (Google/Microsoft Authenticator, \
                             Authy…) para abrir o programa.",
                        );
                        ui.label(
                            "Os perfis e chaves de host passam a ficar cifrados no disco, e você pode \
                             salvar as senhas dos switches.",
                        );
                        ui.add_space(8.0);
                        if ui.button(RichText::new("Ativar senha mestra + 2FA").strong()).clicked() {
                            act = Act::Goto(SecurityDialog::Setup(Setup { step: 1, ..Default::default() }));
                        }
                    }
                    SecurityDialog::Setup(s) => setup_ui(ui, s, &mut act),
                    SecurityDialog::ChangePassword { current, new1, new2, error } => {
                        egui::Grid::new("chpw").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                            password_field(ui, "Senha mestra atual", current);
                            password_field(ui, "Nova senha", new1);
                            password_field(ui, "Repita a nova senha", new2);
                        });
                        ui.add_space(6.0);
                        if ui.button("Trocar senha").clicked() {
                            act = Act::ChangePassword;
                        }
                        error_label(ui, error);
                    }
                    SecurityDialog::Disable { password, code, error } => {
                        ui.colored_label(
                            ORANGE,
                            "A configuração volta para config.json SEM criptografia e as senhas \
                             salvas dos switches são apagadas.",
                        );
                        ui.add_space(6.0);
                        egui::Grid::new("disable").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                            password_field(ui, "Senha mestra", password);
                            ui.label("Código do autenticador");
                            ui.add(egui::TextEdit::singleline(code).desired_width(120.0).hint_text("000000"));
                            ui.end_row();
                        });
                        ui.add_space(6.0);
                        if ui.button("Desativar").clicked() {
                            act = Act::Disable;
                        }
                        error_label(ui, error);
                    }
                    SecurityDialog::Recovery(codes) => {
                        ui.label(RichText::new("Novos códigos de recuperação").strong());
                        ui.label("Os códigos antigos deixaram de valer. Guarde estes fora deste computador.");
                        ui.add_space(4.0);
                        recovery_list(ui, codes);
                        ui.add_space(6.0);
                        if ui.button("Fechar").clicked() {
                            act = Act::Close;
                        }
                    }
                }
            });
        if !open {
            return;
        }
        match act {
            Act::None => self.security = Some(dlg),
            Act::Close => {}
            Act::Goto(d) => self.security = Some(d),
            Act::FinishSetup => self.finish_setup(dlg),
            Act::ChangePassword => self.change_master_password(dlg),
            Act::Disable => self.disable_vault(dlg),
            Act::NewRecovery => {
                let codes = totp::recovery_codes(10);
                if let Some(v) = &mut self.vault {
                    v.recovery = codes.iter().map(|c| totp::normalize_recovery(c)).collect();
                }
                self.save_cfg();
                self.security = Some(SecurityDialog::Recovery(codes));
            }
        }
    }

    fn finish_setup(&mut self, dlg: SecurityDialog) {
        let SecurityDialog::Setup(mut s) = dlg else { return };
        let session = match Vault::create(&s.pw1) {
            Ok(vault) => VaultSession {
                vault,
                totp_secret: std::mem::take(&mut s.secret),
                recovery: s.recovery.iter().map(|c| totp::normalize_recovery(c)).collect(),
                passwords: BTreeMap::new(),
            },
            Err(e) => {
                s.error = Some(e);
                self.security = Some(SecurityDialog::Setup(s));
                return;
            }
        };
        self.cfg.ensure_ids();
        if let Err(e) = session.save(&self.cfg) {
            s.secret = session.totp_secret.clone();
            s.error = Some(format!("Não foi possível gravar o cofre: {e}"));
            self.security = Some(SecurityDialog::Setup(s));
            return;
        }
        // só depois do cofre gravado, remove a configuração em texto puro
        if let Err(e) = fs::remove_file(config_path()) {
            if e.kind() != std::io::ErrorKind::NotFound {
                self.error = Some(format!(
                    "Cofre criado, mas não consegui apagar {}: {e}. Apague-o manualmente.",
                    config_path().display()
                ));
            }
        }
        self.vault = Some(session);
        self.remember_pw = false;
        self.status = "Senha mestra e 2FA ativados. Na próxima abertura serão pedidos senha + código.".into();
    }

    fn change_master_password(&mut self, dlg: SecurityDialog) {
        let SecurityDialog::ChangePassword { current, new1, new2, .. } = dlg else { return };
        let res = if Vault::unlock(&current).is_err() {
            Err("Senha mestra atual incorreta.".to_string())
        } else if new1 != new2 {
            Err("As novas senhas não conferem.".to_string())
        } else {
            match &mut self.vault {
                Some(v) => v.vault.change_password(&new1).and_then(|_| v.save(&self.cfg)),
                None => Err("O cofre não está aberto.".to_string()),
            }
        };
        match res {
            Ok(()) => self.status = "Senha mestra alterada".into(),
            Err(e) => {
                self.security = Some(SecurityDialog::ChangePassword {
                    current: String::new(),
                    new1: String::new(),
                    new2: String::new(),
                    error: Some(e),
                })
            }
        }
    }

    fn disable_vault(&mut self, dlg: SecurityDialog) {
        let SecurityDialog::Disable { password, code, .. } = dlg else { return };
        let check = match Vault::unlock(&password) {
            Ok((_, mut data)) => second_factor(&data.totp_secret, &mut data.recovery_codes, &code)
                .map(|_| ())
                .ok_or_else(|| "Código inválido.".to_string()),
            Err(e) => Err(e),
        };
        let res = check.and_then(|_| self.cfg.save()).and_then(|_| {
            fs::remove_file(vault_path()).map_err(|e| format!("Não consegui apagar o cofre: {e}"))
        });
        match res {
            Ok(()) => {
                self.vault = None;
                self.remember_pw = false;
                self.status = "Senha mestra e 2FA desativados (configuração em config.json, sem criptografia)".into();
            }
            Err(e) => {
                self.security = Some(SecurityDialog::Disable { password: String::new(), code: String::new(), error: Some(e) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codigo_de_recuperacao_vale_uma_vez() {
        let secret = b"12345678901234567890";
        let mut rec = vec![totp::normalize_recovery("ABCDE-FGHJK")];
        assert_eq!(second_factor(secret, &mut rec, "abcde-fghjk"), Some(true));
        assert!(rec.is_empty());
        assert_eq!(second_factor(secret, &mut rec, "ABCDE-FGHJK"), None);
        assert_eq!(second_factor(secret, &mut rec, "000000x"), None);
    }
}
