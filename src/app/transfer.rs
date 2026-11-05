//! Janela de transferência de arquivos (SCP) entre o computador e o switch.

use super::SwitchApp;
use crate::config::{backups_dir, Profile};
use crate::scp::{self, Direction, ScpEvent, ScpHandle, ScpJob};
use eframe::egui::{self, Color32, RichText};
use std::path::PathBuf;

const RED: Color32 = Color32::from_rgb(240, 90, 90);
const GREEN: Color32 = Color32::from_rgb(70, 200, 110);

pub struct TransferDialog {
    direction: Direction,
    local: String,
    remote: String,
    handle: Option<ScpHandle>,
    progress: (u64, u64),
    status: String,
    result: Option<Result<String, String>>,
}

impl TransferDialog {
    pub fn new() -> Self {
        Self {
            direction: Direction::Download,
            local: String::new(),
            remote: String::new(),
            handle: None,
            progress: (0, 0),
            status: String::new(),
            result: None,
        }
    }

    pub fn running(&self) -> bool {
        self.handle.is_some()
    }

    /// Processa eventos do worker; devolve a mensagem de sucesso quando termina.
    fn poll(&mut self) -> Option<String> {
        let h = self.handle.as_ref()?;
        while let Ok(ev) = h.rx.try_recv() {
            match ev {
                ScpEvent::Status(s) => self.status = s,
                ScpEvent::Progress { done, total } => self.progress = (done, total),
                ScpEvent::Done(msg) => {
                    self.result = Some(Ok(msg.clone()));
                    self.handle = None;
                    return Some(msg);
                }
                ScpEvent::Error(e) => {
                    self.result = Some(Err(e));
                    self.handle = None;
                    return None;
                }
            }
        }
        None
    }
}

/// Por que a transferência não pode ser iniciada para este perfil (None = pode).
pub fn unavailable_reason(p: &Profile, has_fingerprint: bool) -> Option<&'static str> {
    if !p.is_ssh() {
        Some("SCP só funciona com perfis SSH (não Telnet).")
    } else if p.host.trim().is_empty() {
        Some("Informe o host do perfil.")
    } else if !has_fingerprint {
        Some("Conecte pelo terminal uma vez para confirmar a chave do host antes de usar SCP.")
    } else {
        None
    }
}

fn file_name_of(path: &str) -> String {
    path.rsplit(['/', '\\', ':']).next().unwrap_or("").to_string()
}

impl SwitchApp {
    /// Perfil usado pela transferência: o da sessão ativa ou o selecionado.
    fn transfer_profile(&self) -> Profile {
        self.view_profile()
    }

    pub(super) fn transfer_fingerprint(&self, p: &Profile) -> Option<String> {
        self.cfg.known_hosts.get(&p.host_key_id()).cloned()
    }

    fn start_transfer(&mut self, ctx: &egui::Context) {
        let p = self.transfer_profile();
        let fingerprint = self.transfer_fingerprint(&p);
        if let Some(why) = unavailable_reason(&p, fingerprint.is_some()) {
            self.error = Some(why.into());
            return;
        }
        let auth = match self.build_auth(&p) {
            Ok(a) => a,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let Some(dlg) = &mut self.transfer else { return };
        let (local, remote) = (dlg.local.trim().to_string(), dlg.remote.trim().to_string());
        if local.is_empty() || remote.is_empty() {
            dlg.result = Some(Err("Preencha o arquivo local e o caminho remoto.".into()));
            return;
        }
        let job = ScpJob {
            host: p.host.trim().to_string(),
            port: p.port,
            user: p.user.trim().to_string(),
            auth,
            fingerprint: fingerprint.unwrap_or_default(),
            direction: dlg.direction,
            local: PathBuf::from(local),
            remote,
        };
        dlg.result = None;
        dlg.progress = (0, 0);
        dlg.status = "Iniciando…".into();
        dlg.handle = Some(scp::spawn(job, ctx.clone()));
    }

    pub(super) fn ui_transfer(&mut self, ctx: &egui::Context) {
        let Some(dlg) = &mut self.transfer else { return };
        if let Some(msg) = dlg.poll() {
            self.status = msg;
        }

        let p = self.transfer_profile();
        let Some(dlg) = &mut self.transfer else { return };
        let mut open = true;
        let mut start = false;
        egui::Window::new("📁 Transferência de arquivos (SCP)")
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.weak(format!("{} — {}:{}", p.display_name(), p.host, p.port));
                ui.add_space(4.0);
                let running = dlg.running();
                ui.add_enabled_ui(!running, |ui| {
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut dlg.direction, Direction::Download, "⬇ Baixar do switch");
                        ui.radio_value(&mut dlg.direction, Direction::Upload, "⬆ Enviar para o switch");
                    });
                    ui.add_space(4.0);
                    egui::Grid::new("scp_grid").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                        ui.label("Remoto:");
                        ui.add(
                            egui::TextEdit::singleline(&mut dlg.remote)
                                .hint_text("ex.: flash:/config.txt  ou  /cfg/startup-config")
                                .desired_width(300.0),
                        );
                        ui.end_row();

                        ui.label("Local:");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut dlg.local).desired_width(220.0));
                            if ui.button("Procurar…").clicked() {
                                let picked = match dlg.direction {
                                    Direction::Upload => rfd::FileDialog::new().pick_file(),
                                    Direction::Download => {
                                        let _ = std::fs::create_dir_all(backups_dir());
                                        let name = file_name_of(&dlg.remote);
                                        rfd::FileDialog::new()
                                            .set_directory(backups_dir())
                                            .set_file_name(if name.is_empty() { "arquivo".into() } else { name })
                                            .save_file()
                                    }
                                };
                                if let Some(path) = picked {
                                    dlg.local = path.display().to_string();
                                    if dlg.direction == Direction::Upload && dlg.remote.trim().is_empty() {
                                        dlg.remote = file_name_of(&dlg.local);
                                    }
                                }
                            }
                        });
                        ui.end_row();
                    });
                });

                ui.add_space(6.0);
                if running {
                    let (done, total) = dlg.progress;
                    let frac = if total > 0 { done as f32 / total as f32 } else { 0.0 };
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .show_percentage()
                            .text(format!("{} / {}", scp::human(done), scp::human(total))),
                    );
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(&dlg.status);
                    });
                    if ui.button("Cancelar").clicked() {
                        if let Some(h) = &dlg.handle {
                            h.cancel();
                        }
                    }
                } else {
                    let label = match dlg.direction {
                        Direction::Download => "⬇ Baixar",
                        Direction::Upload => "⬆ Enviar",
                    };
                    start = ui.button(RichText::new(label).strong()).clicked();
                }

                match &dlg.result {
                    Some(Ok(msg)) => {
                        ui.colored_label(GREEN, format!("✔ {msg}"));
                    }
                    Some(Err(e)) => {
                        ui.colored_label(RED, format!("⚠ {e}"));
                    }
                    None => {}
                }
                ui.add_space(4.0);
                ui.small("Usa uma conexão SSH separada; o terminal continua disponível.");
            });

        if start {
            self.start_transfer(ctx);
        }
        // fechar a janela durante a transferência cancela
        if !open {
            if let Some(h) = self.transfer.as_ref().and_then(|d| d.handle.as_ref()) {
                h.cancel();
            }
            self.transfer = None;
        }
    }
}
