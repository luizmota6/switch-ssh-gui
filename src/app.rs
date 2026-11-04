use crate::config::{logs_dir, AuthKind, Config, Profile};
use crate::ssh::{self, Auth, ConnectParams, FromWorker, SshHandle, ToWorker};
use crate::term::Terminal;
use crate::vendor::{is_dangerous, Vendor};
use crate::vterm::VTerm;
use eframe::egui::{self, Color32, Key, RichText};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(PartialEq)]
enum ConnState {
    Disconnected,
    Connecting,
    HostKey { fingerprint: String, key_type: String },
    Connected,
}

pub struct SwitchApp {
    cfg: Config,
    selected: Option<usize>,
    form: Profile,
    password: String,
    passphrase: String,

    conn: Option<SshHandle>,
    state: ConnState,
    session_profile: Option<Profile>,
    status: String,
    error: Option<String>,

    term: Terminal,
    vterm: VTerm,
    focus_term: bool,
    input: String,
    history: Vec<String>,
    hist_pos: Option<usize>,
    focus_input: bool,
    confirm: Option<String>,

    log: Option<(BufWriter<File>, PathBuf)>,
    last_log_path: Option<PathBuf>,
}

impl SwitchApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let cfg = Config::load();
        let (selected, form) = match cfg.profiles.first() {
            Some(p) => (Some(0), p.clone()),
            None => (None, Profile::default()),
        };
        Self {
            cfg,
            selected,
            form,
            password: String::new(),
            passphrase: String::new(),
            conn: None,
            state: ConnState::Disconnected,
            session_profile: None,
            status: "Desconectado".into(),
            error: None,
            term: Terminal::new(50_000),
            vterm: VTerm::new(120, 40),
            focus_term: false,
            input: String::new(),
            history: Vec::new(),
            hist_pos: None,
            focus_input: false,
            confirm: None,
            log: None,
            last_log_path: None,
        }
    }

    /// Mensagem local exibida no terminal e no buffer de log.
    fn echo(&mut self, msg: &str) {
        self.term.feed(msg);
        self.vterm.process(msg);
    }

    fn save_cfg(&mut self) {
        if let Err(e) = self.cfg.save() {
            self.error = Some(format!("Erro ao salvar configuração: {e}"));
        }
    }

    // ---------- conexão ----------

    fn connect(&mut self, ctx: &egui::Context) {
        let p = self.form.clone();
        if p.host.trim().is_empty() || p.user.trim().is_empty() {
            self.error = Some("Informe host e usuário.".into());
            return;
        }
        let auth = match p.auth {
            AuthKind::Password => Auth::Password(self.password.clone()),
            AuthKind::Key => {
                if p.key_path.trim().is_empty() {
                    self.error = Some("Informe o caminho da chave privada.".into());
                    return;
                }
                Auth::Key {
                    path: PathBuf::from(p.key_path.trim()),
                    passphrase: (!self.passphrase.is_empty()).then(|| self.passphrase.clone()),
                }
            }
        };
        let (cols, rows) = self.vterm.size();
        let params = ConnectParams {
            host: p.host.trim().to_string(),
            port: p.port,
            user: p.user.trim().to_string(),
            auth,
            known_fingerprint: self.cfg.known_hosts.get(&p.host_key_id()).cloned(),
            auto_pager: p.auto_pager,
            init_commands: p.vendor.init_commands().iter().map(|s| s.to_string()).collect(),
            cols,
            rows,
        };
        self.error = None;
        self.echo(&format!(
            "\r\n\x1b[36m===== {} ({}:{}) — {} =====\x1b[0m\r\n",
            p.display_name(),
            p.host,
            p.port,
            chrono::Local::now().format("%d/%m/%Y %H:%M:%S")
        ));
        if self.cfg.log_sessions {
            self.open_log(&p);
        }
        self.session_profile = Some(p);
        self.state = ConnState::Connecting;
        self.conn = Some(ssh::spawn(params, ctx.clone()));
    }

    fn disconnect(&mut self) {
        if let Some(c) = &self.conn {
            c.send(ToWorker::Disconnect);
        }
    }

    fn open_log(&mut self, p: &Profile) {
        let dir = logs_dir();
        if fs::create_dir_all(&dir).is_err() {
            return;
        }
        let safe: String = p
            .display_name()
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = dir.join(format!(
            "{}_{}.log",
            safe,
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        if let Ok(f) = File::create(&path) {
            self.last_log_path = Some(path.clone());
            self.log = Some((BufWriter::new(f), path));
        }
    }

    fn close_log(&mut self) {
        if let Some((mut w, _)) = self.log.take() {
            let tail = self.term.lines.last().cloned().unwrap_or_default();
            let _ = writeln!(w, "{tail}");
            let _ = w.flush();
        }
    }

    fn poll(&mut self) {
        let Some(conn) = &self.conn else { return };
        let events: Vec<FromWorker> = conn.rx.try_iter().collect();
        for ev in events {
            match ev {
                FromWorker::Status(s) => self.status = s,
                FromWorker::HostKeyPrompt { fingerprint, key_type } => {
                    self.status = "Confirme a chave do host".into();
                    self.state = ConnState::HostKey { fingerprint, key_type };
                }
                FromWorker::HostKeyAccepted { fingerprint } => {
                    if let Some(p) = &self.session_profile {
                        self.cfg.known_hosts.insert(p.host_key_id(), fingerprint);
                        self.save_cfg();
                    }
                    self.state = ConnState::Connecting;
                }
                FromWorker::Connected => {
                    self.state = ConnState::Connected;
                    self.status = match &self.session_profile {
                        Some(p) => format!("Conectado: {}@{}:{}", p.user, p.host, p.port),
                        None => "Conectado".into(),
                    };
                    self.focus_term = true;
                }
                FromWorker::Data(s) => {
                    self.vterm.process(&s);
                    let done = self.term.feed(&s);
                    if let Some((w, _)) = &mut self.log {
                        for l in done {
                            let _ = writeln!(w, "{l}");
                        }
                    }
                }
                FromWorker::Error(e) => {
                    self.echo(&format!("\r\n\x1b[31m[ERRO] {e}\x1b[0m\r\n").replace('\n', "\r\n").replace("\r\r\n", "\r\n"));
                    self.error = Some(e);
                }
                FromWorker::Closed => {
                    self.echo("\r\n\x1b[36m===== conexão encerrada =====\x1b[0m\r\n");
                    self.state = ConnState::Disconnected;
                    self.status = "Desconectado".into();
                    self.close_log();
                    self.conn = None;
                    return;
                }
            }
        }
    }

    // ---------- envio ----------

    fn request_send(&mut self, cmd: String) {
        if is_dangerous(&cmd) {
            self.confirm = Some(cmd);
        } else {
            self.send_line(cmd);
        }
    }

    fn send_line(&mut self, cmd: String) {
        if let Some(c) = &self.conn {
            c.send(ToWorker::Send(format!("{cmd}\r").into_bytes()));
        }
        if !cmd.trim().is_empty() && self.history.last() != Some(&cmd) {
            self.history.push(cmd);
            if self.history.len() > 500 {
                self.history.remove(0);
            }
        }
        self.hist_pos = None;
        self.focus_term = true;
    }

    fn send_raw(&self, bytes: &[u8]) {
        if let Some(c) = &self.conn {
            c.send(ToWorker::Send(bytes.to_vec()));
        }
    }

    fn save_output(&mut self) {
        let dir = logs_dir();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!(
            "saida_{}.txt",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        match fs::write(&path, self.term.text()) {
            Ok(()) => self.status = format!("Saída salva em {}", path.display()),
            Err(e) => self.error = Some(format!("Erro ao salvar: {e}")),
        }
    }

    // ---------- UI ----------

    fn ui_profiles(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let busy = self.state != ConnState::Disconnected;
        ui.heading("Switches");
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("profiles")
            .max_height(170.0)
            .show(ui, |ui| {
                let mut pick = None;
                for (i, p) in self.cfg.profiles.iter().enumerate() {
                    let txt = format!("{}  ·  {}", p.display_name(), p.host);
                    if ui
                        .add_enabled(!busy, egui::SelectableLabel::new(self.selected == Some(i), txt))
                        .clicked()
                    {
                        pick = Some(i);
                    }
                }
                if let Some(i) = pick {
                    self.selected = Some(i);
                    self.form = self.cfg.profiles[i].clone();
                    self.password.clear();
                    self.passphrase.clear();
                }
                if self.cfg.profiles.is_empty() {
                    ui.weak("Nenhum perfil salvo.");
                }
            });

        ui.add_enabled_ui(!busy, |ui| {
            ui.horizontal(|ui| {
                if ui.button("➕ Novo").clicked() {
                    self.selected = None;
                    self.form = Profile::default();
                    self.password.clear();
                }
                if ui.button("💾 Salvar").clicked() {
                    let p = self.form.clone();
                    match self.selected {
                        Some(i) => self.cfg.profiles[i] = p,
                        None => {
                            self.cfg.profiles.push(p);
                            self.selected = Some(self.cfg.profiles.len() - 1);
                        }
                    }
                    self.save_cfg();
                    self.status = "Perfil salvo".into();
                }
                if ui
                    .add_enabled(self.selected.is_some(), egui::Button::new("🗑 Excluir"))
                    .clicked()
                {
                    if let Some(i) = self.selected.take() {
                        self.cfg.profiles.remove(i);
                        self.form = Profile::default();
                        self.save_cfg();
                    }
                }
            });
        });

        ui.separator();

        ui.add_enabled_ui(!busy, |ui| {
            egui::Grid::new("form").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Nome");
                ui.text_edit_singleline(&mut self.form.name);
                ui.end_row();
                ui.label("Host/IP");
                ui.text_edit_singleline(&mut self.form.host);
                ui.end_row();
                ui.label("Porta");
                ui.add(egui::DragValue::new(&mut self.form.port).range(1..=65535));
                ui.end_row();
                ui.label("Usuário");
                ui.text_edit_singleline(&mut self.form.user);
                ui.end_row();
                ui.label("Autenticação");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.form.auth, AuthKind::Password, "Senha");
                    ui.radio_value(&mut self.form.auth, AuthKind::Key, "Chave");
                });
                ui.end_row();
                match self.form.auth {
                    AuthKind::Password => {
                        ui.label("Senha");
                        let r = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            self.connect(ctx);
                        }
                        ui.end_row();
                    }
                    AuthKind::Key => {
                        ui.label("Chave privada");
                        ui.text_edit_singleline(&mut self.form.key_path);
                        ui.end_row();
                        ui.label("Passphrase");
                        ui.add(egui::TextEdit::singleline(&mut self.passphrase).password(true));
                        ui.end_row();
                    }
                }
                ui.label("Fabricante");
                egui::ComboBox::from_id_salt("vendor")
                    .selected_text(self.form.vendor.label())
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        for v in Vendor::ALL {
                            ui.selectable_value(&mut self.form.vendor, v, v.label());
                        }
                    });
                ui.end_row();
            });
            ui.checkbox(&mut self.form.auto_pager, "Paginação automática (--More--)");
            ui.label("Comandos personalizados (1 por linha):");
            ui.add(
                egui::TextEdit::multiline(&mut self.form.custom_commands)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .code_editor()
                    .hint_text("show interfaces 1/1/1\nshow arp"),
            );
        });

        if let Some(fp) = self.cfg.known_hosts.get(&self.form.host_key_id()).cloned() {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.small(format!("🔑 {fp}"));
                if ui
                    .add_enabled(!busy, egui::Button::new("Esquecer chave").small())
                    .clicked()
                {
                    self.cfg.known_hosts.remove(&self.form.host_key_id());
                    self.save_cfg();
                }
            });
        }

        ui.separator();
        ui.horizontal(|ui| {
            match self.state {
                ConnState::Disconnected => {
                    let b = egui::Button::new(RichText::new("🔌 Conectar").strong())
                        .fill(Color32::from_rgb(30, 110, 60));
                    if ui.add_sized([120.0, 28.0], b).clicked() {
                        self.connect(ctx);
                    }
                }
                _ => {
                    let b = egui::Button::new(RichText::new("⏏ Desconectar").strong())
                        .fill(Color32::from_rgb(140, 40, 40));
                    if ui.add_sized([120.0, 28.0], b).clicked() {
                        self.disconnect();
                    }
                }
            }
            if ui.checkbox(&mut self.cfg.log_sessions, "Gravar log").changed() {
                self.save_cfg();
            }
        });
    }

    fn ui_quick(&mut self, ui: &mut egui::Ui) {
        let connected = self.state == ConnState::Connected;
        let prof = self.session_profile.clone().unwrap_or_else(|| self.form.clone());
        ui.heading("Comandos rápidos");
        ui.weak(prof.vendor.label());
        ui.add_space(4.0);
        let mut to_send = None;
        egui::ScrollArea::vertical().id_salt("quick").show(ui, |ui| {
            ui.add_enabled_ui(connected, |ui| {
                for (label, cmd) in prof.vendor.quick_commands() {
                    if ui
                        .add_sized([ui.available_width(), 24.0], egui::Button::new(*label))
                        .on_hover_text(*cmd)
                        .clicked()
                    {
                        to_send = Some(cmd.to_string());
                    }
                }
                let custom = prof.custom_list();
                if !custom.is_empty() {
                    ui.separator();
                    ui.label("Personalizados");
                    for cmd in custom {
                        if ui
                            .add_sized([ui.available_width(), 24.0], egui::Button::new(&cmd).truncate())
                            .on_hover_text(&cmd)
                            .clicked()
                        {
                            to_send = Some(cmd);
                        }
                    }
                }
                ui.separator();
                if let Some(sp) = &mut self.session_profile {
                    if ui.checkbox(&mut sp.auto_pager, "Auto --More--").changed() {
                        if let Some(c) = &self.conn {
                            c.send(ToWorker::SetAutoPager(sp.auto_pager));
                        }
                    }
                }
                ui.label("Teclas");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Ctrl+C").clicked() {
                        self.send_raw(b"\x03");
                    }
                    if ui.button("Ctrl+Z").clicked() {
                        self.send_raw(b"\x1a");
                    }
                    if ui.button("Espaço").clicked() {
                        self.send_raw(b" ");
                    }
                    if ui.button("q").clicked() {
                        self.send_raw(b"q");
                    }
                    if ui.button("?").on_hover_text("Ajuda contextual da CLI").clicked() {
                        let line = std::mem::take(&mut self.input);
                        self.send_raw(format!("{line}?").as_bytes());
                    }
                });
            });
        });
        if let Some(cmd) = to_send {
            self.request_send(cmd);
        }
    }

    fn ui_input(&mut self, ui: &mut egui::Ui) {
        let connected = self.state == ConnState::Connected;
        ui.horizontal(|ui| {
            ui.label(RichText::new("❯").monospace().strong());
            let w = ui.available_width() - 420.0;
            let resp = ui.add_enabled(
                connected,
                egui::TextEdit::singleline(&mut self.input)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(w.max(200.0))
                    .hint_text("digite um comando e pressione Enter (↑/↓ histórico)"),
            );
            if self.focus_input && connected {
                resp.request_focus();
                self.focus_input = false;
            }
            if resp.has_focus() {
                let (up, down) = ui.input(|i| (i.key_pressed(Key::ArrowUp), i.key_pressed(Key::ArrowDown)));
                if up && !self.history.is_empty() {
                    let pos = match self.hist_pos {
                        None => self.history.len() - 1,
                        Some(p) => p.saturating_sub(1),
                    };
                    self.hist_pos = Some(pos);
                    self.input = self.history[pos].clone();
                } else if down {
                    if let Some(p) = self.hist_pos {
                        if p + 1 < self.history.len() {
                            self.hist_pos = Some(p + 1);
                            self.input = self.history[p + 1].clone();
                        } else {
                            self.hist_pos = None;
                            self.input.clear();
                        }
                    }
                }
            }
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            let click = ui.add_enabled(connected, egui::Button::new("Enviar")).clicked();
            if enter || click {
                let cmd = std::mem::take(&mut self.input);
                self.request_send(cmd);
            }
            if ui.button("Limpar").clicked() {
                self.term.clear();
                self.vterm.clear();
            }
            if ui.button("Copiar tela").clicked() {
                ui.ctx().copy_text(self.vterm.screen_text());
                self.status = "Tela copiada para a área de transferência".into();
            }
            if ui.button("Copiar tudo").clicked() {
                ui.ctx().copy_text(self.term.text());
                self.status = "Saída copiada para a área de transferência".into();
            }
            if ui.button("Salvar saída").clicked() {
                self.save_output();
            }
        });
    }

    fn ui_terminal(&mut self, ui: &mut egui::Ui) {
        let connected = self.state == ConnState::Connected;
        if self.focus_term && connected {
            self.vterm.request_focus(ui.ctx());
            self.focus_term = false;
        }
        let out = self.vterm.show(ui, connected);
        if let Some(c) = &self.conn {
            if !out.input.is_empty() {
                c.send(ToWorker::Send(out.input));
            }
            if let Some((cols, rows)) = out.resized {
                c.send(ToWorker::Resize(cols, rows));
            }
        }
    }

    fn ui_modals(&mut self, ctx: &egui::Context) {
        if let ConnState::HostKey { fingerprint, key_type } = &self.state {
            let (fp, kt) = (fingerprint.clone(), key_type.clone());
            let mut decision = None;
            egui::Window::new("🔑 Chave de host desconhecida")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Primeira conexão com este switch. Confira o fingerprint antes de aceitar:");
                    ui.add_space(6.0);
                    ui.label(RichText::new(format!("Tipo: {kt}")).monospace());
                    ui.label(RichText::new(&fp).monospace().strong());
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("✔ Aceitar e salvar").clicked() {
                            decision = Some(true);
                        }
                        if ui.button("✖ Rejeitar").clicked() {
                            decision = Some(false);
                        }
                    });
                });
            if let (Some(d), Some(c)) = (decision, &self.conn) {
                c.send(ToWorker::AcceptHostKey(d));
                self.state = ConnState::Connecting;
            }
        }

        if let Some(cmd) = self.confirm.clone() {
            let mut decision = None;
            egui::Window::new("⚠ Confirmar comando")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Este comando pode reiniciar o switch ou apagar configuração:");
                    ui.label(RichText::new(&cmd).monospace().strong().color(Color32::from_rgb(255, 140, 60)));
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Executar mesmo assim").clicked() {
                            decision = Some(true);
                        }
                        if ui.button("Cancelar").clicked() {
                            decision = Some(false);
                        }
                    });
                });
            match decision {
                Some(true) => {
                    self.confirm = None;
                    self.send_line(cmd);
                }
                Some(false) => {
                    self.confirm = None;
                    self.input = cmd;
                }
                None => {}
            }
        }
    }
}

impl eframe::App for SwitchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let color = match self.state {
                    ConnState::Connected => Color32::from_rgb(70, 200, 110),
                    ConnState::Disconnected => Color32::GRAY,
                    _ => Color32::from_rgb(230, 180, 60),
                };
                let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 5.0, color);
                ui.label(&self.status);
                if let Some(p) = &self.last_log_path {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.small(format!("log: {}", p.display()));
                    });
                }
            });
        });

        egui::SidePanel::left("profiles")
            .resizable(true)
            .default_width(330.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().id_salt("left").show(ui, |ui| {
                    self.ui_profiles(ui, ctx);
                });
            });

        egui::SidePanel::right("quick")
            .resizable(true)
            .default_width(190.0)
            .show(ctx, |ui| self.ui_quick(ui));

        egui::TopBottomPanel::bottom("input")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(8.0))
            .show(ctx, |ui| self.ui_input(ui));

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(e) = self.error.clone() {
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::from_rgb(240, 90, 90), format!("⚠ {e}"));
                    if ui.small_button("✖").clicked() {
                        self.error = None;
                    }
                });
            }
            self.ui_terminal(ui);
        });

        self.ui_modals(ctx);
    }
}
