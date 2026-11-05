//! Protetor de tela: "Matrix" (chuva digital verde) ou "Pinguins" (pinguins que caem
//! de guarda-chuva, andam e escalam a interface). Liga após alguns minutos sem uso;
//! qualquer tecla/mouse volta ao normal. Não bloqueia o cofre nem derruba a conexão.

mod penguins;

pub use penguins::Stage;
use crate::config::ScreensaverStyle;
use eframe::egui::{self, pos2, vec2, Color32, FontId, Rect, Vec2};
use penguins::Colony;
use std::time::{Duration, Instant};

/// Caracteres da chuva (as fontes embutidas não têm katakana).
const GLYPHS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&*+=<>?:;|{}[]~";
const FONT_SIZE: f32 = 16.0;
const ROW_H: f32 = 18.0;

/// Tempo após iniciar em que entradas são ignoradas (o clique no botão não fecha na hora).
const GRACE: Duration = Duration::from_millis(600);
const DEMO_GRACE: Duration = Duration::from_secs(10);

/// Gerador pseudoaleatório simples (xorshift) — dispensa dependência extra.
struct Rng(u64);

impl Rng {
    fn seeded() -> Self {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9);
        Self(t | 1)
    }
    fn next(&mut self) -> f32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 40) as f32 / (1u64 << 24) as f32
    }
    fn range(&mut self, a: f32, b: f32) -> f32 {
        a + (b - a) * self.next()
    }
    fn glyph(&mut self) -> char {
        GLYPHS[(self.next() * GLYPHS.len() as f32) as usize % GLYPHS.len()] as char
    }
}

/// Uma coluna da chuva: posição da "cabeça" (em linhas), velocidade e tamanho do rastro.
struct Drop {
    head: f32,
    speed: f32,
    len: f32,
}

impl Drop {
    fn new(rng: &mut Rng, rows: usize, first: bool) -> Self {
        Self {
            // na abertura espalha as cabeças pela tela; depois nascem acima do topo
            head: if first { rng.range(-(rows as f32), rows as f32) } else { -rng.range(0.0, rows as f32 * 0.5) },
            speed: rng.range(7.0, 24.0),
            len: rng.range(8.0, 32.0),
        }
    }
}

struct Rain {
    screen: Rect,
    col_w: f32,
    cols: usize,
    rows: usize,
    glyphs: Vec<char>,
    drops: Vec<Drop>,
    rng: Rng,
}

impl Rain {
    fn new(screen: Rect, col_w: f32) -> Self {
        let mut rng = Rng::seeded();
        let cols = (screen.width() / col_w).ceil().max(1.0) as usize;
        let rows = (screen.height() / ROW_H).ceil().max(1.0) as usize;
        let glyphs = (0..cols * rows).map(|_| rng.glyph()).collect();
        let drops = (0..cols).map(|_| Drop::new(&mut rng, rows, true)).collect();
        Self {
            screen,
            col_w,
            cols,
            rows,
            glyphs,
            drops,
            rng,
        }
    }

    fn step(&mut self, dt: f32) {
        // alguns caracteres trocam sozinhos (efeito "piscando")
        let flips = (self.glyphs.len() as f32 * 1.5 * dt) as usize + 1;
        for _ in 0..flips {
            let i = (self.rng.next() * self.glyphs.len() as f32) as usize % self.glyphs.len();
            self.glyphs[i] = self.rng.glyph();
        }
        for c in 0..self.cols {
            let before = self.drops[c].head as i64;
            self.drops[c].head += self.drops[c].speed * dt;
            let after = self.drops[c].head as i64;
            // caractere novo na cabeça quando ela entra numa linha
            if after != before && (0..self.rows as i64).contains(&after) {
                self.glyphs[after as usize * self.cols + c] = self.rng.glyph();
            }
            if self.drops[c].head - self.drops[c].len > self.rows as f32 {
                self.drops[c] = Drop::new(&mut self.rng, self.rows, false);
            }
        }
    }

    fn paint(&self, painter: &egui::Painter) {
        let font = FontId::monospace(FONT_SIZE);
        painter.rect_filled(self.screen, 0.0, Color32::BLACK);
        for (c, d) in self.drops.iter().enumerate() {
            let head = d.head.floor() as i64;
            let x = self.screen.left() + c as f32 * self.col_w;
            for i in 0..d.len as i64 {
                let row = head - i;
                if row < 0 || row >= self.rows as i64 {
                    continue;
                }
                let color = if i == 0 {
                    Color32::from_rgb(210, 255, 210) // cabeça quase branca
                } else {
                    let fade = 1.0 - i as f32 / d.len;
                    let g = (90.0 + 165.0 * fade) as u8;
                    Color32::from_rgba_unmultiplied(0, g, (40.0 * fade) as u8, (255.0 * fade.powf(0.8)) as u8)
                };
                let ch = self.glyphs[row as usize * self.cols + c];
                painter.text(
                    pos2(x, self.screen.top() + row as f32 * ROW_H),
                    egui::Align2::LEFT_TOP,
                    ch,
                    font.clone(),
                    color,
                );
            }
        }

        // relógio e dica, sobre uma faixa escura para ficarem legíveis
        let center = self.screen.center();
        let clock = chrono::Local::now().format("%H:%M").to_string();
        let band = Rect::from_center_size(center, vec2(260.0, 96.0));
        painter.rect_filled(band, 8.0, Color32::from_rgba_unmultiplied(0, 0, 0, 210));
        painter.text(
            center - vec2(0.0, 10.0),
            egui::Align2::CENTER_CENTER,
            clock,
            FontId::monospace(52.0),
            Color32::from_rgb(120, 255, 140),
        );
        painter.text(
            center + vec2(0.0, 32.0),
            egui::Align2::CENTER_CENTER,
            "qualquer tecla ou mouse para voltar",
            FontId::monospace(11.0),
            Color32::from_rgb(60, 170, 80),
        );
    }
}

enum Scene {
    Matrix(Rain),
    Penguins(Colony),
}

/// Protetor em exibição.
struct Active {
    scene: Scene,
    screen: Rect,
    started: Instant,
    grace: Duration,
    /// fecha no próximo frame (mantém a sobreposição neste para absorver o clique)
    closing: bool,
}

pub struct Screensaver {
    last_activity: Instant,
    active: Option<Active>,
    /// `SWITCH_SSH_PROTETOR=1` (ou `=pinguins`): abre já com o protetor ativo (testes/demonstração).
    demo_pending: Option<ScreensaverStyle>,
}

impl Screensaver {
    pub fn new() -> Self {
        let demo = std::env::var("SWITCH_SSH_PROTETOR").ok().and_then(|v| match v.as_str() {
            "1" | "matrix" => Some(ScreensaverStyle::Matrix),
            "pinguins" => Some(ScreensaverStyle::Pinguins),
            _ => None,
        });
        Self {
            last_activity: Instant::now(),
            active: None,
            demo_pending: demo,
        }
    }

    pub fn start_now(&mut self, ctx: &egui::Context, style: ScreensaverStyle) {
        self.start(ctx, GRACE, style);
    }

    fn start(&mut self, ctx: &egui::Context, grace: Duration, style: ScreensaverStyle) {
        let screen = ctx.screen_rect();
        let scene = match style {
            ScreensaverStyle::Matrix => {
                let col_w = ctx.fonts(|f| f.glyph_width(&FontId::monospace(FONT_SIZE), 'W')) + 4.0;
                Scene::Matrix(Rain::new(screen, col_w))
            }
            ScreensaverStyle::Pinguins => Scene::Penguins(Colony::new(screen)),
        };
        self.active = Some(Active { scene, screen, started: Instant::now(), grace, closing: false });
    }

    /// Chamar no início de cada frame, antes dos widgets.
    /// `minutes` = 0 desliga. Devolve true se o protetor está cobrindo a tela.
    pub fn update(&mut self, ctx: &egui::Context, minutes: u32, style: ScreensaverStyle) -> bool {
        if let Some(demo) = self.demo_pending.filter(|_| ctx.screen_rect().width() > 100.0) {
            self.demo_pending = None;
            self.start(ctx, DEMO_GRACE, demo);
        }
        let active_input = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.delta() != Vec2::ZERO || i.pointer.any_down()
        });

        if let Some(a) = &mut self.active {
            if a.closing {
                self.active = None;
                self.last_activity = Instant::now();
                return false;
            }
            if active_input && a.started.elapsed() > a.grace {
                a.closing = true;
                // a tecla que acordou não vai para o terminal
                ctx.input_mut(|i| i.events.clear());
            }
            return true;
        }

        if active_input {
            self.last_activity = Instant::now();
        }
        if minutes == 0 {
            return false;
        }
        let limit = Duration::from_secs(minutes as u64 * 60);
        let idle = self.last_activity.elapsed();
        if idle >= limit {
            self.start(ctx, GRACE, style);
            return true;
        }
        // acorda o app quando o tempo ocioso vencer
        ctx.request_repaint_after(limit - idle);
        false
    }

    /// Desenha o protetor por cima de tudo (chamar no fim do frame).
    /// `stage` = bordas da interface onde os pinguins andam e escalam.
    pub fn paint(&mut self, ctx: &egui::Context, stage: &Stage) {
        let screen = ctx.screen_rect();
        let Some(a) = &mut self.active else { return };
        // janela redimensionada: a chuva refaz a grade no novo tamanho
        if a.screen != screen && !a.closing {
            if let Scene::Matrix(_) = a.scene {
                let col_w = ctx.fonts(|f| f.glyph_width(&FontId::monospace(FONT_SIZE), 'W')) + 4.0;
                a.scene = Scene::Matrix(Rain::new(screen, col_w));
            }
            a.screen = screen;
        }
        let dt = ctx.input(|i| i.stable_dt).min(0.1);
        match &mut a.scene {
            Scene::Matrix(r) => r.step(dt),
            Scene::Penguins(c) => c.step(dt, screen, stage),
        }

        egui::Area::new(egui::Id::new("screensaver"))
            .order(egui::Order::Foreground)
            .fixed_pos(screen.min)
            .show(ctx, |ui| {
                // ocupa a tela toda e absorve cliques
                ui.allocate_rect(screen, egui::Sense::click_and_drag());
                match &a.scene {
                    Scene::Matrix(r) => r.paint(ui.painter()),
                    Scene::Penguins(c) => {
                        // o app continua visível por baixo, levemente escurecido
                        let p = ui.painter();
                        p.rect_filled(screen, 0.0, Color32::from_rgba_unmultiplied(0, 0, 0, 90));
                        c.paint(p);
                        p.text(
                            pos2(screen.center().x, screen.top() + 14.0),
                            egui::Align2::CENTER_CENTER,
                            "qualquer tecla ou mouse para voltar",
                            FontId::proportional(12.0),
                            Color32::from_gray(200),
                        );
                    }
                }
            });
        ctx.request_repaint();
    }
}
