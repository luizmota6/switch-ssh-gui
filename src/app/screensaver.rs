//! Protetor de tela estilo "chuva digital" (Matrix): colunas de caracteres verdes
//! caindo sobre fundo preto. Liga após alguns minutos sem uso; qualquer tecla/mouse
//! volta ao normal. Só esconde a tela: não bloqueia o cofre nem derruba a conexão.

use eframe::egui::{self, pos2, vec2, Color32, FontId, Rect, Vec2};
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
    started: Instant,
    grace: Duration,
    /// fecha no próximo frame (mantém a sobreposição neste para absorver o clique)
    closing: bool,
}

impl Rain {
    fn new(screen: Rect, col_w: f32, grace: Duration) -> Self {
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
            started: Instant::now(),
            grace,
            closing: false,
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

pub struct Screensaver {
    last_activity: Instant,
    rain: Option<Rain>,
    /// `SWITCH_SSH_PROTETOR=1`: abre já com o protetor ativo (para testes/demonstração).
    demo_pending: bool,
}

impl Screensaver {
    pub fn new() -> Self {
        Self {
            last_activity: Instant::now(),
            rain: None,
            demo_pending: std::env::var_os("SWITCH_SSH_PROTETOR").is_some_and(|v| v == "1"),
        }
    }

    pub fn start_now(&mut self, ctx: &egui::Context) {
        self.start(ctx, GRACE);
    }

    fn start(&mut self, ctx: &egui::Context, grace: Duration) {
        let col_w = ctx.fonts(|f| f.glyph_width(&FontId::monospace(FONT_SIZE), 'W')) + 4.0;
        self.rain = Some(Rain::new(ctx.screen_rect(), col_w, grace));
    }

    /// Chamar no início de cada frame, antes dos widgets.
    /// `minutes` = 0 desliga. Devolve true se o protetor está cobrindo a tela.
    pub fn update(&mut self, ctx: &egui::Context, minutes: u32) -> bool {
        if self.demo_pending && ctx.screen_rect().width() > 100.0 {
            self.demo_pending = false;
            self.start(ctx, DEMO_GRACE);
        }
        let active_input = ctx.input(|i| {
            !i.events.is_empty() || i.pointer.delta() != Vec2::ZERO || i.pointer.any_down()
        });

        if let Some(rain) = &mut self.rain {
            if rain.closing {
                self.rain = None;
                self.last_activity = Instant::now();
                return false;
            }
            if active_input && rain.started.elapsed() > rain.grace {
                rain.closing = true;
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
            self.start(ctx, GRACE);
            return true;
        }
        // acorda o app quando o tempo ocioso vencer
        ctx.request_repaint_after(limit - idle);
        false
    }

    /// Desenha a chuva por cima de tudo (chamar no fim do frame).
    pub fn paint(&mut self, ctx: &egui::Context) {
        let screen = ctx.screen_rect();
        // janela redimensionada: refaz a grade no novo tamanho
        if self.rain.as_ref().is_some_and(|r| r.screen != screen && !r.closing) {
            let grace = self.rain.as_ref().map_or(GRACE, |r| r.grace);
            self.start(ctx, grace);
        }
        let Some(rain) = &mut self.rain else { return };
        let dt = ctx.input(|i| i.stable_dt).min(0.1);
        rain.step(dt);

        egui::Area::new(egui::Id::new("screensaver"))
            .order(egui::Order::Foreground)
            .fixed_pos(screen.min)
            .show(ctx, |ui| {
                // ocupa a tela toda e absorve cliques
                ui.allocate_rect(screen, egui::Sense::click_and_drag());
                rain.paint(ui.painter());
            });
        ctx.request_repaint();
    }
}
