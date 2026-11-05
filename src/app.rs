mod screensaver;
mod security;
mod session;
mod transfer;

use crate::backup::{self, Backup};
use security::{LockScreen, SecurityDialog, VaultSession};
use screensaver::{Screensaver, Stage};
use session::{ConnState, MonitorState, Session, SessionEvent};
use transfer::TransferDialog;
use crate::config::{backups_dir, logs_dir, AuthKind, Config, Profile, Protocol};
use crate::monitor::{self, MonitorJob};
use crate::ssh::{self, Auth, ConnectParams, ToWorker};
use crate::vendor::{is_dangerous, Vendor};
use eframe::egui::{self, Color32, Key, RichText};
use std::fs;
use std::path::PathBuf;

/// Como as sessões abertas são exibidas.
#[derive(Clone, Copy, PartialEq)]
enum SplitLayout {
    /// Uma sessão por vez (a aba ativa).
    Tabs,
    /// Todas lado a lado (colunas).
    Columns,
    /// Todas empilhadas (linhas).
    Rows,
    /// Grade automática (2x2, 3x2, 3x3…).
    Grid,
}

impl SplitLayout {
    const ALL: [SplitLayout; 4] = [SplitLayout::Tabs, SplitLayout::Columns, SplitLayout::Rows, SplitLayout::Grid];

    fn label(self) -> &'static str {
        match self {
            SplitLayout::Tabs => "▣ Abas",
            SplitLayout::Columns => "◫ Lado a lado",
            SplitLayout::Rows => "⬓ Empilhado",
            SplitLayout::Grid => "▦ Grade",
        }
    }

    /// (colunas, linhas) para `n` painéis.
    fn grid(self, n: usize) -> (usize, usize) {
        let n = n.max(1);
        match self {
            SplitLayout::Tabs => (1, 1),
            SplitLayout::Columns => (n, 1),
            SplitLayout::Rows => (1, n),
            SplitLayout::Grid => {
                let cols = (n as f32).sqrt().ceil() as usize;
                (cols, n.div_ceil(cols))
            }
        }
    }
}

pub struct SwitchApp {
    cfg: Config,
    selected: Option<usize>,
    form: Profile,
    password: String,
    passphrase: String,

    /// Sessões abertas (abas / painéis).
    sessions: Vec<Session>,
    /// Índice da sessão ativa (recebe comandos rápidos, backup, barra de comando).
    active: usize,
    next_session_id: u64,
    layout: SplitLayout,
    /// Barra de comando envia para todas as sessões conectadas.
    broadcast: bool,

    status: String,
    error: Option<String>,

    input: String,
    history: Vec<String>,
    hist_pos: Option<usize>,
    focus_input: bool,
    /// Comando perigoso aguardando confirmação (texto, enviar para todas).
    confirm: Option<(String, bool)>,
    /// Perfil aguardando confirmação de fabricante/protocolo antes de conectar.
    confirm_connect: Option<Profile>,

    last_log_path: Option<PathBuf>,
    last_backup_path: Option<PathBuf>,

    /// Janela de transferência SCP aberta.
    transfer: Option<TransferDialog>,

    /// Protetor de tela (chuva digital estilo Matrix).
    screensaver: Screensaver,

    /// Cofre aberto (senha mestra + 2FA ativos). `None` = modo sem cofre (config.json).
    vault: Option<VaultSession>,
    /// Tela de desbloqueio (o app fica inacessível enquanto `Some`).
    locked: Option<LockScreen>,
    security: Option<SecurityDialog>,
    /// Checkbox "lembrar senha no cofre" do perfil em edição.
    remember_pw: bool,
}

impl SwitchApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let locked = crate::vault::exists().then(LockScreen::default);
        // com cofre, a configuração só é carregada depois do desbloqueio
        let cfg = if locked.is_some() { Config::default() } else { Config::load() };
        let mut app = Self {
            cfg,
            selected: None,
            form: Profile::default(),
            password: String::new(),
            passphrase: String::new(),
            sessions: Vec::new(),
            active: 0,
            next_session_id: 1,
            layout: SplitLayout::Tabs,
            broadcast: false,
            status: "Desconectado".into(),
            error: None,
            input: String::new(),
            history: Vec::new(),
            hist_pos: None,
            focus_input: false,
            confirm: None,
            confirm_connect: None,
            last_log_path: None,
            last_backup_path: None,
            transfer: None,
            screensaver: Screensaver::new(),
            vault: None,
            locked,
            security: None,
            remember_pw: false,
        };
        app.after_config_loaded();
        #[cfg(debug_assertions)]
        app.demo_sessions();
        app
    }

    /// Só no build de desenvolvimento: `SWITCH_SSH_DEMO_SESSOES=N` abre N sessões
    /// falsas (sem rede) em grade, para testar a divisão de telas.
    #[cfg(debug_assertions)]
    fn demo_sessions(&mut self) {
        let Some(n) = std::env::var("SWITCH_SSH_DEMO_SESSOES").ok().and_then(|v| v.parse::<usize>().ok()) else {
            return;
        };
        for k in 1..=n.min(9) {
            let p = Profile {
                name: format!("SW-DEMO-{k}"),
                host: format!("10.0.0.{k}"),
                protocol: Some(Protocol::Ssh),
                vendor: Some(Vendor::CiscoIos),
                ..Profile::default()
            };
            let mut s = Session::new(self.next_session_id, p, 80, 24);
            self.next_session_id += 1;
            s.state = ConnState::Connected;
            let cpu = [12.0, 47.0, 71.0, 93.0][(k - 1) % 4];
            s.monitor_state = MonitorState::Running(crate::monitor::Stats {
                cpu_pct: Some(cpu),
                mem_used_kb: 1_300_000 * k as u64,
                mem_total_kb: 8_000_000,
                load: [0.42 * k as f32, 0.30, 0.25],
                uptime_s: 93_784 * k as u64,
                disk_used_kb: 9_000_000,
                disk_total_kb: 20_000_000,
                rx_per_s: Some(1_250_000.0),
                tx_per_s: Some(48_000.0),
                cores: 4,
                cpu_history: (0..60).map(|x| (cpu + 15.0 * ((x as f32) * 0.3).sin()).clamp(0.0, 100.0)).collect(),
                ..Default::default()
            });
            s.echo(&format!(
                "\x1b[36m===== SW-DEMO-{k} (SSH 10.0.0.{k}:22) =====\x1b[0m\r\n\
                 SW-DEMO-{k}#show ip interface brief\r\n\
                 Interface      IP-Address   OK? Method Status   Protocol\r\n\
                 Vlan1          10.0.0.{k}     YES NVRAM  up       up\r\n\
                 Gi1/0/1        unassigned   YES unset  up       up\r\n\
                 Gi1/0/2        unassigned   YES unset  down     down\r\n\
                 SW-DEMO-{k}#"
            ));
            self.sessions.push(s);
        }
        self.layout = SplitLayout::Grid;
    }

    /// Chamado ao carregar a configuração (início ou desbloqueio do cofre).
    fn after_config_loaded(&mut self) {
        self.cfg.ensure_ids();
        match self.cfg.profiles.first().cloned() {
            Some(p) => {
                self.selected = Some(0);
                self.select_form(p);
            }
            None => {
                self.selected = None;
                self.select_form(Profile::default());
            }
        }
    }

    /// Carrega um perfil no formulário (e a senha salva no cofre, se houver).
    fn select_form(&mut self, p: Profile) {
        let saved = self.vault.as_ref().and_then(|v| v.passwords.get(&p.id).cloned());
        self.remember_pw = saved.is_some();
        self.password = saved.unwrap_or_default();
        self.passphrase.clear();
        self.form = p;
    }

    fn save_cfg(&mut self) {
        let res = match &self.vault {
            Some(v) => v.save(&self.cfg),
            None => self.cfg.save(),
        };
        if let Err(e) = res {
            self.error = Some(format!("Erro ao salvar configuração: {e}"));
        }
    }

    // ---------- conexão ----------

    /// Credenciais do perfil a partir da senha/frase digitadas no formulário.
    fn build_auth(&self, p: &Profile) -> Result<Auth, String> {
        Ok(match p.auth {
            // Telnet só tem usuário/senha (digitados no prompt do switch).
            _ if p.is_telnet() => Auth::Password(self.password.clone()),
            AuthKind::Password => Auth::Password(self.password.clone()),
            AuthKind::Key => {
                if p.key_path.trim().is_empty() {
                    return Err("Informe o caminho da chave privada.".into());
                }
                Auth::Key {
                    path: PathBuf::from(p.key_path.trim()),
                    passphrase: (!self.passphrase.is_empty()).then(|| self.passphrase.clone()),
                }
            }
        })
    }

    /// Valida o perfil e abre a confirmação (fabricante/protocolo); só conecta após confirmar.
    fn request_connect(&mut self) {
        let p = self.form.clone();
        // Usuário pode ficar em branco: alguns switches aceitam login sem usuário.
        if p.host.trim().is_empty() {
            self.error = Some("Informe o host.".into());
            return;
        }
        if let Some(msg) = p.missing_choice() {
            self.error = Some(msg.into());
            return;
        }
        if let Err(e) = self.build_auth(&p) {
            self.error = Some(e);
            return;
        }
        self.error = None;
        self.confirm_connect = Some(p);
    }

    /// Abre uma sessão nova (aba/painel) para o perfil e inicia a conexão.
    fn connect(&mut self, ctx: &egui::Context, p: Profile) {
        let Some(protocol) = p.protocol else { return };
        let auth = match self.build_auth(&p) {
            Ok(a) => a,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        // tamanho inicial = o do painel ativo; o painel novo informa o real ao ser desenhado
        let (cols, rows) = self.active_session().map_or((120, 40), |s| s.vterm.size());
        let id = self.next_session_id;
        self.next_session_id += 1;
        let mut s = Session::new(id, p.clone(), cols, rows);

        let params = ConnectParams {
            protocol,
            host: p.host.trim().to_string(),
            port: p.port,
            user: p.user.trim().to_string(),
            auth: auth.clone(),
            known_fingerprint: self.cfg.known_hosts.get(&p.host_key_id()).cloned(),
            auto_pager: p.auto_pager,
            init_commands: p.login_commands().0,
            cols,
            rows,
        };
        self.error = None;
        s.echo(&format!(
            "\x1b[36m===== {} ({} {}:{} · {}) — {} =====\x1b[0m\r\n",
            p.display_name(),
            protocol.label(),
            p.host,
            p.port,
            p.vendor_label(),
            chrono::Local::now().format("%d/%m/%Y %H:%M:%S")
        ));
        for c in p.login_commands().1 {
            s.echo(&format!(
                "\x1b[33m[aviso] comando perigoso não executado no login: {c}\x1b[0m\r\n"
            ));
        }
        if self.cfg.log_sessions {
            if let Some(path) = s.open_log() {
                self.last_log_path = Some(path);
            }
        }
        s.state = ConnState::Connecting;
        s.status = "Conectando…".into();
        s.auth = Some(auth);
        s.conn = Some(ssh::spawn(params, ctx.clone()));
        self.sessions.push(s);
        self.active = self.sessions.len() - 1;
    }

    // ---------- sessões ----------

    fn active_session(&self) -> Option<&Session> {
        self.sessions.get(self.active)
    }

    fn active_session_mut(&mut self) -> Option<&mut Session> {
        self.sessions.get_mut(self.active)
    }

    fn active_connected(&self) -> bool {
        self.active_session().is_some_and(Session::connected)
    }

    /// Perfil cujos comandos/fabricante aparecem no painel direito:
    /// o da sessão ativa, ou o do formulário se não houver sessão.
    fn view_profile(&self) -> Profile {
        self.active_session().map_or_else(|| self.form.clone(), |s| s.profile.clone())
    }

    fn set_active(&mut self, i: usize) {
        if i < self.sessions.len() {
            self.active = i;
        }
    }

    /// Fecha a sessão: desconecta (se viva) e remove a aba.
    fn close_session(&mut self, i: usize) {
        if i >= self.sessions.len() {
            return;
        }
        let mut s = self.sessions.remove(i);
        s.disconnect();
        s.stop_monitor();
        s.close_log();
        if self.active >= self.sessions.len() {
            self.active = self.sessions.len().saturating_sub(1);
        } else if i < self.active {
            self.active -= 1;
        }
    }

    /// Inicia o monitor de recursos (CPU/memória/uptime) da sessão `i`, se for SSH
    /// com a opção ligada no perfil. Chamado ao concluir o login.
    fn start_monitor(&mut self, i: usize, ctx: &egui::Context) {
        let Some(s) = self.sessions.get(i) else { return };
        if s.profile.monitor_resources {
            self.force_start_monitor(i, ctx);
        }
    }

    /// Inicia o monitor ignorando a opção do perfil (botão "monitorar" da barra).
    fn force_start_monitor(&mut self, i: usize, ctx: &egui::Context) {
        let Some(s) = self.sessions.get(i) else { return };
        if !s.profile.is_ssh() || !s.connected() || s.monitor.is_some() {
            return;
        }
        // a chave do host já foi confirmada no login da sessão
        let Some(fingerprint) = self.cfg.known_hosts.get(&s.profile.host_key_id()).cloned() else { return };
        let Some(auth) = s.auth.clone() else { return };
        let job = MonitorJob {
            host: s.profile.host.trim().to_string(),
            port: s.profile.port,
            user: s.profile.user.trim().to_string(),
            auth,
            fingerprint,
        };
        let s = &mut self.sessions[i];
        s.monitor = Some(monitor::spawn(job, ctx.clone()));
        s.monitor_state = MonitorState::Starting;
    }

    fn poll(&mut self, ctx: &egui::Context) {
        for i in 0..self.sessions.len() {
            let events = self.sessions[i].poll();
            let name = self.sessions[i].title();
            for ev in events {
                match ev {
                    SessionEvent::Connected => self.start_monitor(i, ctx),
                    SessionEvent::Status(s) => self.status = format!("[{name}] {s}"),
                    SessionEvent::Error(e) => self.error = Some(format!("[{name}] {e}")),
                    SessionEvent::HostKeyAccepted { host_key_id, fingerprint } => {
                        self.cfg.known_hosts.insert(host_key_id, fingerprint);
                        self.save_cfg();
                    }
                    SessionEvent::Closed { backup_lost } => {
                        if backup_lost {
                            self.error = Some(format!("[{name}] Conexão encerrada durante o backup; nada foi salvo."));
                        }
                        self.status = format!("[{name}] Desconectado");
                    }
                }
            }
        }
    }

    // ---------- backup da configuração ----------

    fn start_backup(&mut self) {
        let Some(s) = self.sessions.get_mut(self.active) else { return };
        if !s.connected() || s.backup.is_some() {
            return;
        }
        let prompt = s.term.lines.last().cloned().unwrap_or_default();
        if !backup::looks_like_prompt(&prompt) {
            self.error = Some(
                "Para o backup, deixe o switch no prompt da CLI (ex.: SW# ou <HPE>) e tente de novo.".into(),
            );
            return;
        }
        let cmd = s.profile.vendor_or_generic().backup_command();
        // a paginação automática precisa estar ligada para a saída vir inteira
        let pager_off = !s.profile.auto_pager;
        if pager_off {
            s.send(ToWorker::SetAutoPager(true));
        }
        s.send_line(cmd);
        s.backup = Some(Backup::new(&prompt, cmd, pager_off));
        self.error = None;
        self.status = format!("[{}] Backup em andamento ({cmd})…", s.title());
    }

    /// Finaliza/cancela o backup da sessão `i`. `cancel` = descarta sem salvar.
    fn finish_backup(&mut self, i: usize, cancel: Option<String>) {
        let Some(s) = self.sessions.get_mut(i) else { return };
        let Some(b) = s.backup.take() else { return };
        if b.restore_pager_off {
            s.send(ToWorker::SetAutoPager(false));
        }
        let name = s.title();
        let ext = s.profile.vendor_or_generic().backup_extension();
        if let Some(msg) = cancel {
            self.error = Some(format!("[{name}] {msg}"));
            self.status = format!("[{name}] Backup cancelado");
            return;
        }
        let cfg = match b.result() {
            Ok(c) => c,
            Err(e) => {
                self.error = Some(format!("[{name}] {e}"));
                self.status = format!("[{name}] Backup falhou");
                return;
            }
        };
        let safe: String = name
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
            .collect();
        let dir = backups_dir();
        let path = dir.join(format!("{}_{}.{ext}", safe, chrono::Local::now().format("%Y%m%d_%H%M%S")));
        let res = fs::create_dir_all(&dir).and_then(|_| fs::write(&path, &cfg));
        match res {
            Ok(()) => {
                self.status = format!(
                    "[{name}] Backup salvo ({} linhas): {}",
                    cfg.lines().count(),
                    path.display()
                );
                self.last_backup_path = Some(path);
            }
            Err(e) => self.error = Some(format!("Erro ao gravar backup em {}: {e}", path.display())),
        }
    }

    /// Verifica os backups em andamento de todas as sessões.
    fn check_backups(&mut self, ctx: &egui::Context) {
        for i in 0..self.sessions.len() {
            let Some(b) = &self.sessions[i].backup else { continue };
            if b.done() {
                self.finish_backup(i, None);
            } else if b.last_data.elapsed() > backup::IDLE_TIMEOUT {
                self.finish_backup(
                    i,
                    Some(format!(
                        "Backup sem resposta do switch há {} s; cancelado (nada foi salvo).",
                        backup::IDLE_TIMEOUT.as_secs()
                    )),
                );
            } else {
                ctx.request_repaint_after(std::time::Duration::from_millis(500));
            }
        }
    }

    // ---------- envio ----------

    /// Envia um comando (com confirmação se perigoso) à sessão ativa ou, com
    /// `all`, a todas as sessões conectadas.
    fn request_send(&mut self, cmd: String, all: bool) {
        if is_dangerous(&cmd) {
            self.confirm = Some((cmd, all));
        } else {
            self.send_line(cmd, all);
        }
    }

    fn send_line(&mut self, cmd: String, all: bool) {
        if all {
            for s in self.sessions.iter().filter(|s| s.connected()) {
                s.send_line(&cmd);
            }
        } else if let Some(s) = self.active_session_mut() {
            s.send_line(&cmd);
            s.focus_term = true;
        }
        if !cmd.trim().is_empty() && self.history.last() != Some(&cmd) {
            self.history.push(cmd);
            if self.history.len() > 500 {
                self.history.remove(0);
            }
        }
        self.hist_pos = None;
    }

    fn send_raw(&self, bytes: &[u8]) {
        if let Some(s) = self.active_session() {
            s.send(ToWorker::Send(bytes.to_vec()));
        }
    }

    fn save_output(&mut self) {
        let Some(s) = self.active_session() else { return };
        let dir = logs_dir();
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!(
            "saida_{}.txt",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        ));
        match fs::write(&path, s.term.text()) {
            Ok(()) => self.status = format!("Saída salva em {}", path.display()),
            Err(e) => self.error = Some(format!("Erro ao salvar: {e}")),
        }
    }

    // ---------- UI ----------

    fn ui_profiles(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Switches");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔒 Segurança").clicked() {
                    self.security = Some(SecurityDialog::menu());
                }
                if self.vault.is_some()
                    && ui.button("Bloquear").on_hover_text("Fecha o cofre e volta para a tela de senha + código").clicked()
                {
                    self.lock();
                }
            });
        });
        ui.add_space(4.0);

        egui::ScrollArea::vertical()
            .id_salt("profiles")
            .max_height(170.0)
            .show(ui, |ui| {
                let mut pick = None;
                for (i, p) in self.cfg.profiles.iter().enumerate() {
                    let txt = format!("{}  ·  {}  ·  {}", p.display_name(), p.host, p.protocol_label());
                    if ui
                        .add(egui::SelectableLabel::new(self.selected == Some(i), txt))
                        .clicked()
                    {
                        pick = Some(i);
                    }
                }
                if let Some(i) = pick {
                    self.selected = Some(i);
                    self.select_form(self.cfg.profiles[i].clone());
                }
                if self.cfg.profiles.is_empty() {
                    ui.weak("Nenhum perfil salvo.");
                }
            });

        ui.scope(|ui| {
            ui.horizontal(|ui| {
                if ui.button("➕ Novo").clicked() {
                    self.selected = None;
                    self.select_form(Profile::default());
                }
                if ui.button("💾 Salvar").clicked() {
                    if self.form.id.is_empty() {
                        self.form.id = crate::config::new_id();
                    }
                    let p = self.form.clone();
                    if let Some(v) = &mut self.vault {
                        if self.remember_pw && !self.password.is_empty() {
                            v.passwords.insert(p.id.clone(), self.password.clone());
                        } else {
                            v.passwords.remove(&p.id);
                        }
                    }
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
                        let removed = self.cfg.profiles.remove(i);
                        if let Some(v) = &mut self.vault {
                            v.passwords.remove(&removed.id);
                        }
                        self.select_form(Profile::default());
                        self.save_cfg();
                    }
                }
            });
        });

        ui.separator();

        ui.scope(|ui| {
            egui::Grid::new("form").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
                ui.label("Nome");
                ui.text_edit_singleline(&mut self.form.name);
                ui.end_row();
                required_label(ui, "Protocolo", self.form.protocol.is_none());
                ui.horizontal(|ui| {
                    let before = self.form.protocol;
                    ui.radio_value(&mut self.form.protocol, Some(Protocol::Ssh), "SSH");
                    ui.radio_value(&mut self.form.protocol, Some(Protocol::Telnet), "Telnet");
                    // troca a porta junto, se ainda estava na padrão (de qualquer protocolo)
                    if let Some(new) = self.form.protocol.filter(|_| self.form.protocol != before) {
                        if [Protocol::Ssh, Protocol::Telnet].iter().any(|p| p.default_port() == self.form.port) {
                            self.form.port = new.default_port();
                        }
                    }
                });
                ui.end_row();
                ui.label("Host/IP");
                ui.text_edit_singleline(&mut self.form.host);
                ui.end_row();
                ui.label("Porta");
                ui.add(egui::DragValue::new(&mut self.form.port).range(1..=65535));
                ui.end_row();
                let telnet = self.form.is_telnet();
                ui.label("Usuário");
                ui.add(egui::TextEdit::singleline(&mut self.form.user).hint_text("(opcional)"))
                    .on_hover_text(if telnet {
                        "Preenchido: enviado sozinho no prompt de login. Em branco: digite no terminal."
                    } else {
                        "Pode ficar em branco se o switch aceitar login sem usuário."
                    });
                ui.end_row();
                if !telnet {
                    ui.label("Autenticação");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut self.form.auth, AuthKind::Password, "Senha");
                        ui.radio_value(&mut self.form.auth, AuthKind::Key, "Chave");
                    });
                    ui.end_row();
                }
                match if telnet { AuthKind::Password } else { self.form.auth } {
                    AuthKind::Password => {
                        ui.label("Senha");
                        let r = ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                            self.request_connect();
                        }
                        ui.end_row();
                        ui.label("");
                        let has_vault = self.vault.is_some();
                        ui.add_enabled(has_vault, egui::Checkbox::new(&mut self.remember_pw, "Lembrar senha no cofre"))
                            .on_hover_text("Guardada cifrada no cofre ao clicar em 💾 Salvar.")
                            .on_disabled_hover_text("Ative a senha mestra em 🔒 Segurança para poder salvar senhas.");
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
                required_label(ui, "Fabricante", self.form.vendor.is_none());
                let selected = match self.form.vendor {
                    Some(v) => RichText::new(v.label()),
                    None => RichText::new("— selecione o fabricante —").color(ORANGE),
                };
                egui::ComboBox::from_id_salt("vendor")
                    .selected_text(selected)
                    .width(210.0)
                    .show_ui(ui, |ui| {
                        for v in Vendor::ALL {
                            ui.selectable_value(&mut self.form.vendor, Some(v), v.label());
                        }
                    });
                ui.end_row();
            });
            if let Some(msg) = self.form.missing_choice() {
                ui.colored_label(ORANGE, format!("⚠ {msg}"));
            }
            if self.form.is_telnet() {
                ui.colored_label(
                    Color32::from_rgb(230, 180, 60),
                    "⚠ Telnet não é criptografado: senha e comandos trafegam em texto puro.",
                );
            }
            ui.checkbox(&mut self.form.auto_pager, "Paginação automática (--More--)");
            let ssh = !self.form.is_telnet();
            ui.add_enabled(
                ssh,
                egui::Checkbox::new(&mut self.form.monitor_resources, "Monitorar CPU/memória/uptime (servidor Linux)"),
            )
            .on_hover_text(
                "Mostra embaixo do terminal o uso de CPU, memória, disco, rede, carga e o \
                 tempo ligado (uptime), atualizado a cada 2 s. Abre uma conexão SSH extra e \
                 silenciosa. Em switches não funciona (desliga sozinho); desmarque para \
                 evitar o login extra.",
            )
            .on_disabled_hover_text("Disponível só para SSH");
            ui.label("Comandos personalizados (1 por linha):");
            ui.add(
                egui::TextEdit::multiline(&mut self.form.custom_commands)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .code_editor()
                    .hint_text("show interfaces 1/1/1\nshow arp"),
            );
            ui.checkbox(&mut self.form.run_custom_on_login, "Executar após o login")
                .on_hover_text(
                    "Envia os comandos acima, em ordem, logo depois do login \
                     (após os comandos do fabricante). Linhas com # são ignoradas; \
                     comandos perigosos (reload, erase…) nunca rodam automaticamente. \
                     Sem marcar, eles ficam só como botões em Comandos rápidos.",
                );
        });

        let fp = self
            .form
            .is_ssh()
            .then(|| self.cfg.known_hosts.get(&self.form.host_key_id()).cloned())
            .flatten();
        if let Some(fp) = fp {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.small(format!("🔑 {fp}"));
                if ui
                    .add(egui::Button::new("Esquecer chave").small())
                    .clicked()
                {
                    self.cfg.known_hosts.remove(&self.form.host_key_id());
                    self.save_cfg();
                }
            });
        }

        ui.separator();
        ui.horizontal(|ui| {
            let why_not = self.form.missing_choice();
            let b = egui::Button::new(RichText::new("🔌 Conectar").strong())
                .fill(Color32::from_rgb(30, 110, 60));
            if ui
                .add_enabled_ui(why_not.is_none(), |ui| ui.add_sized([120.0, 28.0], b))
                .inner
                .on_hover_text("Abre uma nova sessão (aba) para este perfil")
                .on_disabled_hover_text(why_not.unwrap_or(""))
                .clicked()
            {
                self.request_connect();
            }
            if ui.checkbox(&mut self.cfg.log_sessions, "Gravar log").changed() {
                self.save_cfg();
            }
        });
        // desconectar = derrubar a conexão E fechar a aba da sessão ativa
        if let Some(s) = self.active_session() {
            let (text, tip) = if s.alive() {
                (
                    format!("⏏ Desconectar \"{}\"", s.title()),
                    "Desconecta a sessão ativa e fecha a aba dela",
                )
            } else {
                // conexão já caiu (erro, exit…): a aba ficou aberta para mostrar o motivo
                (format!("✖ Fechar aba \"{}\"", s.title()), "Fecha a aba da sessão ativa (já desconectada)")
            };
            let b = egui::Button::new(RichText::new(text).strong())
                .fill(Color32::from_rgb(140, 40, 40))
                .truncate();
            if ui
                .add_sized([ui.available_width().min(260.0), 26.0], b)
                .on_hover_text(tip)
                .clicked()
            {
                let name = s.title();
                self.close_session(self.active);
                self.status = format!("[{name}] Desconectado e aba fechada");
            }
        }
    }

    fn ui_quick(&mut self, ui: &mut egui::Ui) {
        let connected = self.active_connected();
        let prof = self.view_profile();
        ui.heading("Comandos rápidos");
        if let Some(s) = self.active_session() {
            ui.label(RichText::new(format!("Sessão: {}", s.title())).strong());
        }
        match prof.vendor {
            Some(v) => ui.weak(v.label()),
            None => ui.colored_label(ORANGE, "Fabricante não definido"),
        };
        ui.add_space(4.0);

        // backup da configuração (SSH ou Telnet) — da sessão ativa
        let mut do_backup = false;
        let mut cancel_backup = false;
        if let Some(b) = self.active_session().and_then(|s| s.backup.as_ref()) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("Backup… {} linhas", b.lines_captured()));
            });
            cancel_backup = ui.small_button("Cancelar backup").clicked();
        } else {
            do_backup = ui
                .add_enabled(
                    connected,
                    egui::Button::new(RichText::new("📥 Backup da configuração").strong())
                        .min_size(egui::vec2(ui.available_width(), 28.0)),
                )
                .on_hover_text(format!(
                    "Executa '{}' e salva em {}",
                    prof.vendor_or_generic().backup_command(),
                    backups_dir().display()
                ))
                .clicked();
        }
        if ui.small_button("📂 Abrir pasta de backups").clicked() {
            let dir = backups_dir();
            let _ = fs::create_dir_all(&dir);
            open_in_file_manager(&dir);
        }
        if let Some(name) = self.last_backup_path.as_ref().and_then(|p| p.file_name()) {
            ui.small(format!("Último: {}", name.to_string_lossy()));
        }
        // transferência de arquivos (SCP, sessão SSH separada)
        let has_fp = self.transfer_fingerprint(&prof).is_some();
        let why_not = transfer::unavailable_reason(&prof, has_fp);
        let scp_btn = ui
            .add_enabled(
                why_not.is_none(),
                egui::Button::new("📁 Transferir arquivo (SCP)").min_size(egui::vec2(ui.available_width(), 24.0)),
            )
            .on_hover_text("Enviar ou baixar arquivos (firmware, configuração) via SCP")
            .on_disabled_hover_text(why_not.unwrap_or(""));
        if scp_btn.clicked() && self.transfer.is_none() {
            self.transfer = Some(TransferDialog::new());
        }
        if do_backup {
            self.start_backup();
        }
        if cancel_backup {
            self.finish_backup(self.active, Some("Backup cancelado pelo usuário (nada foi salvo).".into()));
        }
        ui.separator();

        let mut to_send = None;
        egui::ScrollArea::vertical().id_salt("quick").show(ui, |ui| {
            ui.add_enabled_ui(connected, |ui| {
                for (label, cmd) in prof.vendor_or_generic().quick_commands() {
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
                if let Some(s) = self.sessions.get_mut(self.active) {
                    if ui.checkbox(&mut s.profile.auto_pager, "Auto --More--").changed() {
                        s.send(ToWorker::SetAutoPager(s.profile.auto_pager));
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
        // comandos rápidos são do fabricante da sessão ativa: vão só para ela
        if let Some(cmd) = to_send {
            self.request_send(cmd, false);
        }
    }

    fn ui_input(&mut self, ui: &mut egui::Ui) {
        let n_connected = self.sessions.iter().filter(|s| s.connected()).count();
        let connected = if self.broadcast { n_connected > 0 } else { self.active_connected() };
        ui.horizontal(|ui| {
            let label = if self.broadcast {
                RichText::new(format!("❯❯ todas ({n_connected})")).monospace().strong().color(ORANGE)
            } else {
                RichText::new("❯").monospace().strong()
            };
            ui.label(label);
            let w = ui.available_width() - 490.0;
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
                self.request_send(cmd, self.broadcast);
            }
            ui.checkbox(&mut self.broadcast, "Enviar para todas")
                .on_hover_text(
                    "Envia o que for digitado nesta barra para TODAS as sessões conectadas \
                     ao mesmo tempo. Teclas digitadas direto num terminal continuam indo só para ele.",
                );
            if ui.button("Limpar").clicked() {
                if let Some(s) = self.active_session_mut() {
                    s.term.clear();
                    s.vterm.clear();
                }
            }
            if ui.button("Copiar tela").clicked() {
                if let Some(s) = self.active_session() {
                    ui.ctx().copy_text(s.vterm.screen_text());
                    self.status = "Tela copiada para a área de transferência".into();
                }
            }
            if ui.button("Copiar tudo").clicked() {
                if let Some(s) = self.active_session() {
                    ui.ctx().copy_text(s.term.text());
                    self.status = "Saída copiada para a área de transferência".into();
                }
            }
            if ui.button("Salvar saída").clicked() {
                self.save_output();
            }
        });
    }

    /// Abas das sessões + seletor de divisão de tela.
    fn ui_tabs(&mut self, ui: &mut egui::Ui) {
        let mut pick = None;
        let mut close = None;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Sessões").strong());
            ui.weak(format!("({})", self.sessions.len()));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                for l in SplitLayout::ALL.iter().rev() {
                    ui.selectable_value(&mut self.layout, *l, l.label()).on_hover_text(match l {
                        SplitLayout::Tabs => "Uma sessão por vez; troque pelas abas",
                        SplitLayout::Columns => "Todas as sessões lado a lado",
                        SplitLayout::Rows => "Todas as sessões empilhadas",
                        SplitLayout::Grid => "Todas as sessões em grade (2x2, 3x2…)",
                    });
                }
                ui.weak("Divisão:");
            });
        });
        if self.sessions.is_empty() {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (i, s) in self.sessions.iter().enumerate() {
                let active = i == self.active;
                let fill = if active { Color32::from_rgb(38, 62, 96) } else { Color32::from_gray(38) };
                egui::Frame::new()
                    .fill(fill)
                    .corner_radius(4.0)
                    .inner_margin(egui::Margin::symmetric(6, 2))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(r.center(), 4.0, s.state_color());
                            let mut text = RichText::new(s.title());
                            if active {
                                text = text.strong().color(Color32::WHITE);
                            }
                            let hover = format!("{} — {}:{}\n{}", s.profile.vendor_label(), s.profile.host, s.profile.port, s.status);
                            if ui
                                .add(egui::Label::new(text).sense(egui::Sense::click()))
                                .on_hover_text(hover)
                                .clicked()
                            {
                                pick = Some(i);
                            }
                            let tip = if s.alive() { "Desconectar e fechar" } else { "Fechar aba" };
                            if ui.small_button("✖").on_hover_text(tip).clicked() {
                                close = Some(i);
                            }
                        });
                    });
            }
        });
        if let Some(i) = pick {
            self.set_active(i);
            if let Some(s) = self.active_session_mut() {
                s.focus_term = true;
            }
        }
        if let Some(i) = close {
            self.close_session(i);
        }
    }

    /// Terminais: só a aba ativa (modo Abas) ou todos divididos na área central.
    fn ui_panes(&mut self, ui: &mut egui::Ui) {
        let area = ui.available_rect_before_wrap();
        ui.advance_cursor_after_rect(area);
        if self.sessions.is_empty() {
            ui.painter().rect_filled(area, 4.0, Color32::from_rgb(14, 16, 20));
            ui.painter().text(
                area.center(),
                egui::Align2::CENTER_CENTER,
                "Nenhuma sessão aberta.\nEscolha um perfil à esquerda e clique em 🔌 Conectar.\nCada conexão abre uma aba; use \"Divisão\" para ver várias ao mesmo tempo.",
                egui::FontId::proportional(14.0),
                Color32::from_gray(130),
            );
            return;
        }
        let split = self.layout != SplitLayout::Tabs && self.sessions.len() > 1;
        let visible: Vec<usize> = if split { (0..self.sessions.len()).collect() } else { vec![self.active] };
        let (cols, rows) = if split { self.layout.grid(visible.len()) } else { (1, 1) };
        let gap = 6.0;
        let header_h = if split { 22.0 } else { 0.0 };
        let cell = egui::vec2(
            (area.width() - gap * (cols as f32 - 1.0)) / cols as f32,
            (area.height() - gap * (rows as f32 - 1.0)) / rows as f32,
        );

        let mut new_active = None;
        // (sessão, true = iniciar / false = parar) pedido pelo botão da barra de monitor
        let mut monitor_action: Option<(usize, bool)> = None;
        for (k, &i) in visible.iter().enumerate() {
            let (c, r) = (k % cols, k / cols);
            let rect = egui::Rect::from_min_size(
                area.min + egui::vec2(c as f32 * (cell.x + gap), r as f32 * (cell.y + gap)),
                cell,
            );
            let is_active = i == self.active;
            let s = &mut self.sessions[i];

            if split {
                // cabeçalho do painel: nome + estado; clicar ativa
                let hdr = egui::Rect::from_min_size(rect.min, egui::vec2(rect.width(), header_h));
                let fill = if is_active { Color32::from_rgb(38, 62, 96) } else { Color32::from_gray(32) };
                ui.painter().rect_filled(hdr, 3.0, fill);
                ui.painter().circle_filled(hdr.left_center() + egui::vec2(10.0, 0.0), 4.0, s.state_color());
                ui.painter().with_clip_rect(hdr).text(
                    hdr.left_center() + egui::vec2(20.0, 0.0),
                    egui::Align2::LEFT_CENTER,
                    format!("{}   {}", s.title(), s.profile.host),
                    egui::FontId::proportional(12.5),
                    if is_active { Color32::WHITE } else { Color32::from_gray(170) },
                );
                if ui.interact(hdr, egui::Id::new(("pane_hdr", s.id)), egui::Sense::click()).clicked() {
                    new_active = Some(i);
                    s.focus_term = true;
                }
            }

            // barra de monitoramento (uptime/CPU/memória…) embaixo do terminal, só em SSH
            let bar_h = monitor_bar_height(s, rect.width());
            let show_bar = bar_h > 0.0;
            let term_rect = egui::Rect::from_min_max(
                rect.min + egui::vec2(0.0, header_h),
                rect.max - egui::vec2(0.0, bar_h),
            );
            if show_bar {
                let bar = egui::Rect::from_min_max(egui::pos2(rect.min.x, rect.max.y - bar_h), rect.max);
                if let Some(start) = monitor_bar(ui, bar, s) {
                    monitor_action = Some((i, start));
                }
            }
            let connected = s.connected();
            if s.focus_term && connected {
                s.vterm.request_focus(ui.ctx());
                s.focus_term = false;
            }
            let out = ui
                .scope_builder(egui::UiBuilder::new().max_rect(term_rect), |ui| s.vterm.show(ui, connected))
                .inner;
            if (out.clicked || out.focused) && !is_active {
                new_active = Some(i);
            }
            if !out.input.is_empty() {
                s.send(ToWorker::Send(out.input));
            }
            if let Some((c, r)) = out.resized {
                s.send(ToWorker::Resize(c, r));
            }
            if split && is_active {
                ui.painter().rect_stroke(
                    rect.expand(1.5),
                    4.0,
                    egui::Stroke::new(1.5_f32, Color32::from_rgb(70, 130, 200)),
                    egui::StrokeKind::Outside,
                );
            }
        }
        if let Some(i) = new_active {
            self.set_active(i);
        }
        match monitor_action {
            Some((i, true)) => {
                let ctx = ui.ctx().clone();
                self.force_start_monitor(i, &ctx);
            }
            Some((i, false)) => self.sessions[i].stop_monitor(),
            None => {}
        }
    }

    /// Confirmação obrigatória antes de cada conexão: mostra fabricante, protocolo,
    /// destino e os comandos que serão enviados ao switch.
    fn ui_confirm_connect(&mut self, ctx: &egui::Context) {
        let Some(p) = self.confirm_connect.clone() else { return };
        let (Some(vendor), Some(protocol)) = (p.vendor, p.protocol) else {
            self.confirm_connect = None;
            return;
        };
        let mut decision = None;
        egui::Window::new("🔌 Confirmar conexão")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Confira se o fabricante e o tipo de conexão correspondem a este equipamento:");
                ui.add_space(6.0);
                egui::Grid::new("confirm_conn").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    ui.label("Switch:");
                    ui.label(RichText::new(p.display_name()).strong());
                    ui.end_row();
                    ui.label("Destino:");
                    ui.label(RichText::new(format!("{}:{}", p.host.trim(), p.port)).monospace());
                    ui.end_row();
                    ui.label("Fabricante:");
                    ui.label(RichText::new(vendor.label()).strong().color(Color32::from_rgb(110, 180, 255)));
                    ui.end_row();
                    ui.label("Protocolo:");
                    let pc = if protocol == Protocol::Telnet { ORANGE } else { Color32::from_rgb(70, 200, 110) };
                    ui.label(RichText::new(protocol.label()).strong().color(pc));
                    ui.end_row();
                    ui.label("Usuário:");
                    ui.label(if p.user.trim().is_empty() { "(sem usuário)" } else { p.user.trim() });
                    ui.end_row();
                    ui.label("Autenticação:");
                    ui.label(match (protocol, p.auth) {
                        (Protocol::Telnet, _) => "senha no prompt de login".to_string(),
                        (_, AuthKind::Password) => "senha".to_string(),
                        (_, AuthKind::Key) => format!("chave {}", p.key_path.trim()),
                    });
                    ui.end_row();
                    ui.label("Paginação auto:");
                    ui.label(if p.auto_pager { "ligada" } else { "desligada" });
                    ui.end_row();
                    if protocol == Protocol::Ssh {
                        ui.label("Monitor:");
                        ui.label(if p.monitor_resources {
                            "CPU/memória/uptime (conexão extra)"
                        } else {
                            "desligado"
                        });
                        ui.end_row();
                    }
                });
                ui.add_space(6.0);
                ui.label("Comandos enviados após o login:");
                let vendor_init = vendor.init_commands();
                let (init, skipped) = p.login_commands();
                if init.is_empty() {
                    ui.weak("  (nenhum)");
                } else {
                    for (i, c) in init.iter().enumerate() {
                        let origem = if i < vendor_init.len() { "fabricante" } else { "personalizado" };
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("  {c}")).monospace());
                            ui.weak(format!("({origem})"));
                        });
                    }
                }
                for c in &skipped {
                    ui.colored_label(ORANGE, format!("⚠ Não será executado (perigoso): {c}"));
                }
                if !p.run_custom_on_login && !p.custom_list().is_empty() {
                    ui.weak("  Comandos personalizados não rodam no login (opção desmarcada).");
                }
                if let Some(w) = p.port_mismatch() {
                    ui.add_space(4.0);
                    ui.colored_label(ORANGE, format!("⚠ {w}"));
                }
                if protocol == Protocol::Telnet {
                    ui.colored_label(ORANGE, "⚠ Telnet não é criptografado: senha e comandos trafegam em texto puro.");
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ok = egui::Button::new(RichText::new("✔ Conectar").strong()).fill(Color32::from_rgb(30, 110, 60));
                    if ui.add(ok).clicked() {
                        decision = Some(true);
                    }
                    if ui.button("✖ Cancelar").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        decision = Some(false);
                    }
                });
            });
        match decision {
            Some(true) => {
                self.confirm_connect = None;
                self.connect(ctx, p);
            }
            Some(false) => self.confirm_connect = None,
            None => {}
        }
    }

    fn ui_modals(&mut self, ctx: &egui::Context) {
        self.ui_confirm_connect(ctx);
        // uma confirmação de chave por vez (a primeira sessão que estiver aguardando)
        let pending = self.sessions.iter().enumerate().find_map(|(i, s)| match &s.state {
            ConnState::HostKey { fingerprint, key_type } => {
                Some((i, s.title(), s.profile.host.clone(), fingerprint.clone(), key_type.clone()))
            }
            _ => None,
        });
        if let Some((i, name, host, fp, kt)) = pending {
            let mut decision = None;
            egui::Window::new("🔑 Chave de host desconhecida")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(RichText::new(format!("Sessão: {name} ({host})")).strong());
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
            if let Some(d) = decision {
                let s = &mut self.sessions[i];
                s.send(ToWorker::AcceptHostKey(d));
                s.state = ConnState::Connecting;
            }
        }

        if let Some((cmd, all)) = self.confirm.clone() {
            let targets: Vec<String> = if all {
                self.sessions.iter().filter(|s| s.connected()).map(Session::title).collect()
            } else {
                self.active_session().map(Session::title).into_iter().collect()
            };
            let mut decision = None;
            egui::Window::new("⚠ Confirmar comando")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Este comando pode reiniciar o switch ou apagar configuração:");
                    ui.label(RichText::new(&cmd).monospace().strong().color(Color32::from_rgb(255, 140, 60)));
                    ui.add_space(6.0);
                    if targets.len() > 1 {
                        ui.colored_label(ORANGE, format!("⚠ Será enviado para {} sessões:", targets.len()));
                    } else {
                        ui.label("Destino:");
                    }
                    for t in &targets {
                        ui.label(RichText::new(format!("  • {t}")).monospace());
                    }
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
                    self.send_line(cmd, all);
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

const ORANGE: Color32 = Color32::from_rgb(230, 180, 60);

/// Verde / amarelo / vermelho conforme o uso.
fn usage_color(pct: f32) -> Color32 {
    if pct >= 85.0 {
        Color32::from_rgb(220, 70, 60)
    } else if pct >= 60.0 {
        Color32::from_rgb(220, 170, 40)
    } else {
        Color32::from_rgb(60, 170, 90)
    }
}

// ---------------- barra de monitoramento (cartões) ----------------

const TILE_H: f32 = 48.0;
const TILE_GAP: f32 = 6.0;
const BAR_PAD: f32 = 5.0;
/// Largura mínima confortável de um cartão.
const TILE_MIN_W: f32 = 110.0;
const MON_TILES: usize = 6;

/// Cartões por linha e número de linhas para a largura disponível.
fn tile_grid(width: f32) -> (usize, usize) {
    let per_row = (((width - 2.0 * BAR_PAD + TILE_GAP) / (TILE_MIN_W + TILE_GAP)).floor() as usize).clamp(2, MON_TILES);
    (per_row, MON_TILES.div_ceil(per_row))
}

/// Altura da barra de monitoramento de uma sessão (0 = sem barra).
fn monitor_bar_height(s: &Session, width: f32) -> f32 {
    if !s.profile.is_ssh() {
        return 0.0;
    }
    match &s.monitor_state {
        MonitorState::Running(_) => {
            let (_, rows) = tile_grid(width);
            rows as f32 * TILE_H + (rows as f32 - 1.0) * TILE_GAP + 2.0 * BAR_PAD
        }
        MonitorState::Off if !s.connected() => 0.0,
        _ => 30.0,
    }
}

/// Um cartão: título pequeno, valor grande colorido, barra fina de uso embaixo
/// e (opcional) gráfico de histórico ao fundo.
struct Tile<'a> {
    title: &'a str,
    value: String,
    detail: String,
    /// 0–100 para a barra de uso; None = sem barra.
    pct: Option<f32>,
    color: Color32,
    history: Option<&'a [f32]>,
    /// Valores em fonte monoespaçada (setas de rede).
    mono: bool,
    hover: String,
}

fn paint_tile(ui: &mut egui::Ui, rect: egui::Rect, t: &Tile, id: egui::Id) {
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 6.0, Color32::from_rgb(30, 35, 44));
    // faixa colorida à esquerda indica o estado da métrica
    p.rect_filled(
        egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
        egui::CornerRadius { nw: 6, sw: 6, ne: 0, se: 0 },
        t.color,
    );

    if let Some(h) = t.history.filter(|h| h.len() >= 2) {
        let area = rect.shrink2(egui::vec2(6.0, 6.0));
        let step = area.width() / 59.0;
        let start = 60usize.saturating_sub(h.len());
        let pts: Vec<egui::Pos2> = h
            .iter()
            .enumerate()
            .map(|(k, v)| {
                egui::pos2(
                    area.left() + (start + k) as f32 * step,
                    area.bottom() - (v / 100.0).clamp(0.0, 1.0) * area.height(),
                )
            })
            .collect();
        p.add(egui::Shape::line(pts, egui::Stroke::new(1.5_f32, t.color.gamma_multiply(0.35))));
    }

    let x = rect.left() + 11.0;
    p.text(
        egui::pos2(x, rect.top() + 5.0),
        egui::Align2::LEFT_TOP,
        t.title,
        egui::FontId::proportional(10.5),
        Color32::from_gray(150),
    );
    // a fonte monoespaçada tem as setas ↓ ↑ (a proporcional não)
    let (value_font, detail_font) = if t.mono {
        (egui::FontId::monospace(13.0), egui::FontId::monospace(11.0))
    } else {
        (egui::FontId::proportional(17.0), egui::FontId::proportional(11.0))
    };
    let value_y = if t.mono { 17.0 } else { 18.0 };
    let value_rect = p.text(egui::pos2(x, rect.top() + value_y), egui::Align2::LEFT_TOP, &t.value, value_font, Color32::WHITE);
    if !t.detail.is_empty() {
        // sem barra de uso: o detalhe vai na linha de baixo (cabe em cartões estreitos)
        let (pos, align) = if t.pct.is_none() {
            (egui::pos2(x, rect.bottom() - 3.0), egui::Align2::LEFT_BOTTOM)
        } else {
            (egui::pos2(value_rect.right() + 6.0, value_rect.bottom() - 2.0), egui::Align2::LEFT_BOTTOM)
        };
        p.text(pos, align, &t.detail, detail_font, Color32::from_gray(160));
    }
    if let Some(pct) = t.pct {
        let track = egui::Rect::from_min_max(
            egui::pos2(x, rect.bottom() - 7.0),
            egui::pos2(rect.right() - 8.0, rect.bottom() - 4.0),
        );
        p.rect_filled(track, 1.5, Color32::from_gray(55));
        let fill = egui::Rect::from_min_size(
            track.min,
            egui::vec2(track.width() * (pct / 100.0).clamp(0.0, 1.0), track.height()),
        );
        p.rect_filled(fill, 1.5, t.color);
    }
    ui.interact(rect, id, egui::Sense::hover()).on_hover_text(&t.hover);
}

/// Barra de monitoramento do servidor embaixo do terminal (estilo MobaXterm):
/// uptime, CPU, memória, disco, rede e carga em cartões. Devolve `Some(true)`
/// para iniciar ou `Some(false)` para parar o monitor.
fn monitor_bar(ui: &mut egui::Ui, rect: egui::Rect, s: &Session) -> Option<bool> {
    ui.painter().rect_filled(rect, 4.0, Color32::from_rgb(18, 21, 27));
    let mut action = None;

    let MonitorState::Running(st) = &s.monitor_state else {
        // estados sem dados: uma linha simples com mensagem e botão
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(rect.shrink2(egui::vec2(10.0, 4.0)))
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
            |ui| {
                ui.set_clip_rect(rect);
                match &s.monitor_state {
                    MonitorState::Off => {
                        ui.label(RichText::new("📊 Monitor do servidor desligado").color(Color32::from_gray(150)));
                        if ui.button("▶ Monitorar").on_hover_text("Mostrar uptime, CPU, memória, disco e rede").clicked() {
                            action = Some(true);
                        }
                    }
                    MonitorState::Starting => {
                        ui.spinner();
                        ui.label(RichText::new("Conectando o monitor do servidor…").color(Color32::from_gray(170)));
                    }
                    MonitorState::Unsupported(why) => {
                        ui.label(RichText::new("📊 Monitor indisponível: o equipamento não é um servidor Linux").color(Color32::from_gray(150)))
                            .on_hover_text(why);
                        if ui.button("↻ Tentar de novo").clicked() {
                            action = Some(true);
                        }
                    }
                    MonitorState::Failed(why) => {
                        ui.label(RichText::new("⚠ Monitor falhou").color(Color32::from_rgb(240, 90, 90)))
                            .on_hover_text(why);
                        if ui.button("↻ Tentar de novo").clicked() {
                            action = Some(true);
                        }
                    }
                    MonitorState::Running(_) => {}
                }
            },
        );
        return action;
    };

    let gb = |kb: u64| kb as f64 / 1024.0 / 1024.0;
    let blue = Color32::from_rgb(90, 160, 240);
    let neutral = Color32::from_rgb(120, 130, 150);
    let cpu = st.cpu_pct.unwrap_or(0.0);
    let load_pct = if st.cores > 0 { st.load[0] / st.cores as f32 * 100.0 } else { 0.0 };
    let tiles = [
        Tile {
            title: "⏱ LIGADO HÁ",
            value: monitor::human_uptime(st.uptime_s),
            detail: String::new(),
            pct: None,
            color: blue,
            history: None,
            mono: false,
            hover: "Uptime: tempo desde o último boot do servidor".into(),
        },
        Tile {
            title: "CPU",
            value: st.cpu_pct.map_or("…".into(), |c| format!("{c:.0}%")),
            detail: format!("{} núcleos", st.cores),
            pct: st.cpu_pct,
            color: usage_color(cpu),
            history: Some(&st.cpu_history),
            mono: false,
            hover: "Uso de CPU (gráfico: últimos ~2 minutos)".into(),
        },
        Tile {
            title: "MEMÓRIA",
            value: format!("{:.0}%", st.mem_pct()),
            detail: format!("{:.1} / {:.1} GB", gb(st.mem_used_kb), gb(st.mem_total_kb)),
            pct: Some(st.mem_pct()),
            color: usage_color(st.mem_pct()),
            history: None,
            mono: false,
            hover: if st.swap_total_kb > 0 {
                format!("Swap: {:.1} de {:.1} GB", gb(st.swap_used_kb), gb(st.swap_total_kb))
            } else {
                "Sem swap".into()
            },
        },
        Tile {
            title: "DISCO /",
            value: format!("{:.0}%", st.disk_pct()),
            detail: format!("{:.0} / {:.0} GB", gb(st.disk_used_kb), gb(st.disk_total_kb)),
            pct: Some(st.disk_pct()),
            color: usage_color(st.disk_pct()),
            history: None,
            mono: false,
            hover: "Uso da partição raiz (/)".into(),
        },
        Tile {
            title: "REDE",
            value: st.rx_per_s.map_or("…".into(), |rx| format!("↓ {}/s", monitor::human_bytes(rx))),
            detail: st.tx_per_s.map_or(String::new(), |tx| format!("↑ {}/s", monitor::human_bytes(tx))),
            pct: None,
            color: neutral,
            history: None,
            mono: true,
            hover: "Tráfego total das interfaces (sem loopback): ↓ recebido  ↑ enviado".into(),
        },
        Tile {
            title: "CARGA",
            value: format!("{:.2}", st.load[0]),
            detail: format!("{:.2} · {:.2}", st.load[1], st.load[2]),
            pct: Some(load_pct.min(100.0)),
            color: usage_color(load_pct),
            history: None,
            mono: false,
            hover: format!("Load average 1 / 5 / 15 min ({} núcleos)", st.cores),
        },
    ];

    let inner = rect.shrink(BAR_PAD);
    let (per_row, _) = tile_grid(rect.width());
    let w = (inner.width() - TILE_GAP * (per_row as f32 - 1.0)) / per_row as f32;
    for (k, t) in tiles.iter().enumerate() {
        let (c, r) = (k % per_row, k / per_row);
        let tr = egui::Rect::from_min_size(
            inner.min + egui::vec2(c as f32 * (w + TILE_GAP), r as f32 * (TILE_H + TILE_GAP)),
            egui::vec2(w, TILE_H),
        );
        paint_tile(ui, tr, t, egui::Id::new(("mon_tile", s.id, k)));
    }

    // botão discreto para parar, no canto do primeiro cartão
    let stop = egui::Rect::from_min_size(
        egui::pos2(inner.min.x + w - 20.0, inner.min.y + 3.0),
        egui::vec2(16.0, 16.0),
    );
    let r = ui.interact(stop, egui::Id::new(("mon_stop", s.id)), egui::Sense::click());
    let c = if r.hovered() { Color32::from_gray(220) } else { Color32::from_gray(90) };
    // "x" desenhado com traços (o glifo ✕ não existe na fonte padrão)
    let (m, k) = (stop.center(), 3.5);
    let st = egui::Stroke::new(1.5_f32, c);
    ui.painter().line_segment([m + egui::vec2(-k, -k), m + egui::vec2(k, k)], st);
    ui.painter().line_segment([m + egui::vec2(-k, k), m + egui::vec2(k, -k)], st);
    if r.on_hover_text("Parar o monitor desta sessão").clicked() {
        action = Some(false);
    }
    action
}

/// Rótulo de campo obrigatório: laranja com "*" enquanto não preenchido.
fn required_label(ui: &mut egui::Ui, text: &str, missing: bool) {
    if missing {
        ui.label(RichText::new(format!("{text} *")).color(ORANGE).strong());
    } else {
        ui.label(text);
    }
}

fn open_in_file_manager(dir: &std::path::Path) {
    #[cfg(windows)]
    let prog = "explorer";
    #[cfg(target_os = "macos")]
    let prog = "open";
    #[cfg(all(unix, not(target_os = "macos")))]
    let prog = "xdg-open";
    let _ = std::process::Command::new(prog).arg(dir).spawn();
}

impl eframe::App for SwitchApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        self.screensaver
            .update(ctx, self.cfg.screensaver_minutes, self.cfg.screensaver_style);
        if self.locked.is_some() {
            self.ui_lock_screen(ctx);
            self.screensaver.paint(ctx, &Stage::window(ctx.screen_rect()));
            return;
        }
        self.check_backups(ctx);

        let status_rect = egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let color = self.active_session().map_or(Color32::GRAY, Session::state_color);
                let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 5.0, color);
                let n = self.sessions.iter().filter(|s| s.connected()).count();
                if !self.sessions.is_empty() {
                    ui.small(format!("{n}/{} conectadas", self.sessions.len()));
                    ui.separator();
                }
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button(RichText::new("▶").color(Color32::from_rgb(90, 220, 110)))
                        .on_hover_text("Iniciar o protetor de tela agora")
                        .clicked()
                    {
                        self.screensaver.start_now(ctx, self.cfg.screensaver_style);
                    }
                    let before = self.cfg.screensaver_style;
                    egui::ComboBox::from_id_salt("ss_style")
                        .selected_text(self.cfg.screensaver_style.label())
                        .width(80.0)
                        .show_ui(ui, |ui| {
                            for s in crate::config::ScreensaverStyle::ALL {
                                ui.selectable_value(&mut self.cfg.screensaver_style, s, s.label());
                            }
                        })
                        .response
                        .on_hover_text("Estilo do protetor de tela");
                    if self.cfg.screensaver_style != before {
                        self.save_cfg();
                    }
                    let r = ui
                        .add(
                            egui::DragValue::new(&mut self.cfg.screensaver_minutes)
                                .range(0..=120)
                                .suffix(" min"),
                        )
                        .on_hover_text("Protetor de tela após este tempo sem uso (0 = desligado)");
                    if r.changed() && !r.dragged() || r.drag_stopped() {
                        self.save_cfg();
                    }
                    ui.small("Protetor:");
                    if let Some(p) = &self.last_log_path {
                        ui.separator();
                        ui.small(format!("log: {}", p.display()));
                    }
                });
            });
        })
        .response
        .rect;

        let left_rect = egui::SidePanel::left("profiles")
            .resizable(true)
            .default_width(330.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().id_salt("left").show(ui, |ui| {
                    self.ui_profiles(ui);
                });
            })
            .response
            .rect;

        let right_rect = egui::SidePanel::right("quick")
            .resizable(true)
            .default_width(190.0)
            .show(ctx, |ui| self.ui_quick(ui))
            .response
            .rect;

        let input_rect = egui::TopBottomPanel::bottom("input")
            .frame(egui::Frame::side_top_panel(&ctx.style()).inner_margin(8.0))
            .show(ctx, |ui| self.ui_input(ui))
            .response
            .rect;

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(e) = self.error.clone() {
                ui.horizontal(|ui| {
                    ui.colored_label(Color32::from_rgb(240, 90, 90), format!("⚠ {e}"));
                    if ui.small_button("✖").clicked() {
                        self.error = None;
                    }
                });
            }
            self.ui_tabs(ui);
            ui.add_space(2.0);
            self.ui_panes(ui);
        });

        self.ui_modals(ctx);
        self.ui_transfer(ctx);
        self.ui_security(ctx);

        // cenário dos pinguins: andam no topo da barra de comando e do rodapé,
        // e escalam as bordas dos painéis laterais e da janela
        let screen = ctx.screen_rect();
        let stage = Stage {
            floors: vec![
                (status_rect.top(), screen.left(), screen.right()),
                (input_rect.top(), input_rect.left(), input_rect.right()),
            ],
            walls: vec![
                (screen.left(), screen.top(), status_rect.top()),
                (screen.right(), screen.top(), status_rect.top()),
                (left_rect.right(), left_rect.top(), left_rect.bottom()),
                (right_rect.left(), right_rect.top(), right_rect.bottom()),
            ],
        };
        self.screensaver.paint(ctx, &stage);
    }
}

#[cfg(test)]
mod tests {
    use super::SplitLayout;

    #[test]
    fn grade_de_paineis() {
        assert_eq!(SplitLayout::Tabs.grid(5), (1, 1));
        assert_eq!(SplitLayout::Columns.grid(3), (3, 1));
        assert_eq!(SplitLayout::Rows.grid(3), (1, 3));
        assert_eq!(SplitLayout::Grid.grid(1), (1, 1));
        assert_eq!(SplitLayout::Grid.grid(2), (2, 1));
        assert_eq!(SplitLayout::Grid.grid(3), (2, 2));
        assert_eq!(SplitLayout::Grid.grid(4), (2, 2));
        assert_eq!(SplitLayout::Grid.grid(5), (3, 2));
        assert_eq!(SplitLayout::Grid.grid(9), (3, 3));
    }
}
