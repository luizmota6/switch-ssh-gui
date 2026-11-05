//! Protetor de tela "Pinguins" (inspirado na ideia do WinPenguins/xpenguins, com
//! desenho e comportamento próprios): pinguins caem de guarda-chuva, andam sobre as
//! bordas da interface, escalam as paredes dos painéis e pulam lá de cima.

use super::Rng;
use eframe::egui::{self, pos2, vec2, Color32, Painter, Pos2, Rect, Shape, Stroke};

const BLACK: Color32 = Color32::from_rgb(22, 24, 30);
const WHITE: Color32 = Color32::from_rgb(244, 245, 248);
const ORANGE: Color32 = Color32::from_rgb(250, 165, 30);
/// Altura do pinguim em pixels.
const H: f32 = 24.0;
const MAX: usize = 14;
const WALK_SPEED: f32 = 34.0;
const CLIMB_SPEED: f32 = 26.0;
const FLOAT_SPEED: f32 = 52.0;

const UMBRELLAS: [Color32; 6] = [
    Color32::from_rgb(230, 70, 70),
    Color32::from_rgb(70, 150, 240),
    Color32::from_rgb(250, 200, 50),
    Color32::from_rgb(90, 200, 110),
    Color32::from_rgb(200, 100, 220),
    Color32::from_rgb(250, 140, 50),
];

/// Onde os pinguins podem pisar e escalar (bordas da interface do app).
#[derive(Clone, Default)]
pub struct Stage {
    /// Chão: (y, x inicial, x final).
    pub floors: Vec<(f32, f32, f32)>,
    /// Paredes verticais: (x, y topo, y base).
    pub walls: Vec<(f32, f32, f32)>,
}

impl Stage {
    /// Só as bordas da janela (ex.: tela de desbloqueio).
    pub fn window(screen: Rect) -> Self {
        Self {
            floors: vec![(screen.bottom(), screen.left(), screen.right())],
            walls: vec![
                (screen.left(), screen.top(), screen.bottom()),
                (screen.right(), screen.top(), screen.bottom()),
            ],
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    /// Descendo de guarda-chuva.
    Float,
    Walk,
    /// Subindo uma parede até `top`.
    Climb { top: f32 },
}

struct Penguin {
    /// Posição dos pés (centro).
    pos: Pos2,
    dir: f32,
    state: State,
    phase: f32,
    umbrella: Color32,
}

pub struct Colony {
    penguins: Vec<Penguin>,
    spawn_in: f32,
    rng: Rng,
}

impl Colony {
    pub fn new(screen: Rect) -> Self {
        let mut c = Self { penguins: Vec::new(), spawn_in: 0.0, rng: Rng::seeded() };
        for _ in 0..4 {
            c.spawn(screen);
        }
        c
    }

    fn spawn(&mut self, screen: Rect) {
        let rng = &mut self.rng;
        let p = Penguin {
            pos: pos2(rng.range(screen.left() + 30.0, screen.right() - 30.0), screen.top() - rng.range(0.0, 120.0)),
            dir: if rng.next() < 0.5 { -1.0 } else { 1.0 },
            state: State::Float,
            phase: rng.range(0.0, 6.0),
            umbrella: UMBRELLAS[(rng.next() * UMBRELLAS.len() as f32) as usize % UMBRELLAS.len()],
        };
        self.penguins.push(p);
    }

    pub fn step(&mut self, dt: f32, screen: Rect, stage: &Stage) {
        // chegam mais pinguins aos poucos
        self.spawn_in -= dt;
        if self.spawn_in <= 0.0 && self.penguins.len() < MAX {
            self.spawn(screen);
            self.spawn_in = self.rng.range(1.0, 2.5);
        }
        for i in 0..self.penguins.len() {
            let r = self.rng.next();
            step_one(&mut self.penguins[i], dt, screen, stage, r);
        }
    }

    pub fn paint(&self, painter: &Painter) {
        for p in &self.penguins {
            match p.state {
                State::Float => draw_floating(painter, p),
                State::Walk => draw_side(painter, p, false),
                State::Climb { .. } => draw_side(painter, p, true),
            }
        }
    }
}

fn step_one(p: &mut Penguin, dt: f32, screen: Rect, stage: &Stage, r: f32) {
    match p.state {
        State::Float => {
            let prev_y = p.pos.y;
            p.phase += dt * 2.0;
            p.pos.y += FLOAT_SPEED * dt;
            p.pos.x += (p.dir * 16.0 + p.phase.sin() * 10.0) * dt;
            if p.pos.x < screen.left() + 10.0 || p.pos.x > screen.right() - 10.0 {
                p.dir = -p.dir;
                p.pos.x = p.pos.x.clamp(screen.left() + 10.0, screen.right() - 10.0);
            }
            // pousa no primeiro chão atravessado neste passo
            let landing = stage
                .floors
                .iter()
                .filter(|(y, x0, x1)| p.pos.x >= *x0 + 4.0 && p.pos.x <= *x1 - 4.0 && prev_y <= *y && p.pos.y >= *y)
                .map(|(y, _, _)| *y)
                .fold(None, |acc: Option<f32>, y| Some(acc.map_or(y, |a| a.min(y))));
            if let Some(y) = landing {
                p.pos.y = y;
                p.state = State::Walk;
                p.phase = 0.0;
            } else if p.pos.y > screen.bottom() + H {
                // caiu para fora: volta pelo alto
                p.pos = pos2(p.pos.x, screen.top() - H);
            }
        }
        State::Walk => {
            p.phase += dt * 10.0;
            // de vez em quando dá meia-volta
            if r < dt * 0.08 {
                p.dir = -p.dir;
            }
            let next_x = p.pos.x + p.dir * WALK_SPEED * dt;
            let feet = p.pos.y - 2.0;
            // parede no caminho: escala
            let wall = stage.walls.iter().find(|(x, y0, y1)| {
                let crosses = if p.dir > 0.0 { p.pos.x < *x && next_x >= *x - 6.0 } else { p.pos.x > *x && next_x <= *x + 6.0 };
                crosses && *y0 < feet && *y1 >= feet
            });
            if let Some((x, top, _)) = wall {
                p.pos.x = x - p.dir * 6.0;
                p.state = State::Climb { top: *top };
                p.phase = 0.0;
                return;
            }
            p.pos.x = next_x;
            // acabou o chão: cai (de guarda-chuva)
            let on_floor = stage
                .floors
                .iter()
                .any(|(y, x0, x1)| (y - p.pos.y).abs() < 1.0 && p.pos.x >= *x0 && p.pos.x <= *x1);
            if !on_floor {
                p.state = State::Float;
            }
        }
        State::Climb { top } => {
            p.phase += dt * 8.0;
            p.pos.y -= CLIMB_SPEED * dt;
            // chegou ao topo da parede: pula para o outro lado e abre o guarda-chuva
            if p.pos.y - H <= top {
                p.dir = -p.dir;
                p.pos.x += p.dir * 12.0;
                p.pos.y = p.pos.y.max(screen.top() + H);
                p.state = State::Float;
                p.phase = 0.0;
            }
        }
    }
}

fn ellipse(p: &Painter, c: Pos2, r: egui::Vec2, color: Color32) {
    p.add(Shape::ellipse_filled(c, r, color));
}

/// Pinguim de lado (andando ou escalando), virado para `dir`.
fn draw_side(painter: &Painter, p: &Penguin, climbing: bool) {
    let f = p.dir;
    let s = p.phase.sin();
    let feet = p.pos;
    let bob = if climbing { 0.0 } else { s.abs() * 0.04 * H };
    let c = feet - vec2(0.0, 0.48 * H + bob);
    let at = |dx: f32, dy: f32| c + vec2(dx * H * f, dy * H);

    // pés (alternando)
    let (la, lb) = if climbing {
        (s * 0.08 * H, -s * 0.08 * H)
    } else {
        (s.max(0.0) * 0.06 * H, (-s).max(0.0) * 0.06 * H)
    };
    ellipse(painter, at(0.0, 0.46) - vec2(0.0, la), vec2(0.11 * H, 0.045 * H), ORANGE);
    ellipse(painter, at(0.12, 0.46) - vec2(0.0, lb), vec2(0.11 * H, 0.045 * H), ORANGE);

    // corpo e barriga
    ellipse(painter, c, vec2(0.27 * H, 0.42 * H), BLACK);
    ellipse(painter, at(0.07, 0.07), vec2(0.17 * H, 0.32 * H), WHITE);
    // asa: levantada ao escalar, balançando ao andar
    let wing = if climbing { at(0.12, -0.22) } else { at(-0.06, 0.02) + vec2(0.0, s * 0.03 * H) };
    ellipse(painter, wing, vec2(0.07 * H, 0.2 * H), Color32::from_rgb(45, 48, 58));

    // cabeça, olho e bico
    let head = at(0.04, -0.42);
    painter.circle_filled(head, 0.21 * H, BLACK);
    painter.circle_filled(head + vec2(0.1 * H * f, -0.02 * H), 0.06 * H, WHITE);
    painter.circle_filled(head + vec2(0.12 * H * f, -0.02 * H), 0.03 * H, Color32::BLACK);
    let base = head + vec2(0.17 * H * f, 0.03 * H);
    let mut beak = vec![base - vec2(0.0, 0.04 * H), base + vec2(0.13 * H * f, 0.01 * H), base + vec2(0.0, 0.05 * H)];
    if f < 0.0 {
        beak.reverse();
    }
    painter.add(Shape::convex_polygon(beak, ORANGE, Stroke::NONE));
}

/// Pinguim de frente segurando o guarda-chuva.
fn draw_floating(painter: &Painter, p: &Penguin) {
    let sway = p.phase.sin() * 0.12;
    let feet = p.pos;
    let c = feet - vec2(0.0, 0.48 * H);

    // guarda-chuva (meia-lua) e cabo
    let top = c - vec2(-sway * H, 1.25 * H);
    let r = 0.62 * H;
    let canopy: Vec<Pos2> = (0..=16)
        .map(|k| {
            let a = std::f32::consts::PI + std::f32::consts::PI * k as f32 / 16.0;
            top + vec2(a.cos() * r, a.sin() * r * 0.75)
        })
        .collect();
    painter.add(Shape::convex_polygon(canopy, p.umbrella, Stroke::NONE));
    painter.line_segment([top, c + vec2(0.18 * H, -0.2 * H)], Stroke::new(1.5_f32, Color32::from_gray(200)));

    // pés pendurados
    ellipse(painter, feet + vec2(-0.1 * H, -0.03 * H), vec2(0.09 * H, 0.04 * H), ORANGE);
    ellipse(painter, feet + vec2(0.1 * H, -0.03 * H), vec2(0.09 * H, 0.04 * H), ORANGE);
    // corpo de frente
    ellipse(painter, c, vec2(0.3 * H, 0.42 * H), BLACK);
    ellipse(painter, c + vec2(0.0, 0.07 * H), vec2(0.2 * H, 0.31 * H), WHITE);
    // asa segurando o cabo
    ellipse(painter, c + vec2(0.25 * H, -0.12 * H), vec2(0.06 * H, 0.17 * H), Color32::from_rgb(45, 48, 58));
    // cabeça com dois olhos e bico
    let head = c - vec2(0.0, 0.4 * H);
    painter.circle_filled(head, 0.22 * H, BLACK);
    for side in [-1.0f32, 1.0] {
        painter.circle_filled(head + vec2(side * 0.08 * H, -0.02 * H), 0.055 * H, WHITE);
        painter.circle_filled(head + vec2(side * 0.08 * H, -0.01 * H), 0.028 * H, Color32::BLACK);
    }
    ellipse(painter, head + vec2(0.0, 0.09 * H), vec2(0.08 * H, 0.04 * H), ORANGE);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(screen: Rect) -> Stage {
        Stage {
            floors: vec![(500.0, 0.0, 800.0)],
            walls: vec![(screen.left(), screen.top(), 500.0), (screen.right(), screen.top(), 500.0)],
        }
    }

    #[test]
    fn cai_pousa_anda_e_escala() {
        let screen = Rect::from_min_size(pos2(0.0, 0.0), vec2(800.0, 600.0));
        let st = stage(screen);
        let mut p = Penguin { pos: pos2(400.0, 0.0), dir: 1.0, state: State::Float, phase: 0.0, umbrella: ORANGE };
        // cai até o chão (y = 500)
        for _ in 0..2000 {
            step_one(&mut p, 0.02, screen, &st, 1.0);
            if p.state == State::Walk {
                break;
            }
        }
        assert!(p.state == State::Walk && (p.pos.y - 500.0).abs() < 0.01);
        // anda até a parede da direita e começa a escalar
        for _ in 0..5000 {
            step_one(&mut p, 0.02, screen, &st, 1.0);
            if matches!(p.state, State::Climb { .. }) {
                break;
            }
        }
        assert!(matches!(p.state, State::Climb { .. }));
        assert!(p.pos.x > 780.0);
        // sobe até o topo e pula de guarda-chuva para o lado oposto
        for _ in 0..5000 {
            step_one(&mut p, 0.02, screen, &st, 1.0);
            if p.state == State::Float {
                break;
            }
        }
        assert!(p.state == State::Float && p.dir < 0.0);
    }

    #[test]
    fn fim_do_chao_vira_queda() {
        let screen = Rect::from_min_size(pos2(0.0, 0.0), vec2(800.0, 600.0));
        let st = Stage { floors: vec![(300.0, 100.0, 200.0)], walls: vec![] };
        let mut p = Penguin { pos: pos2(195.0, 300.0), dir: 1.0, state: State::Walk, phase: 0.0, umbrella: ORANGE };
        for _ in 0..50 {
            step_one(&mut p, 0.02, screen, &st, 1.0);
        }
        assert!(p.state == State::Float);
    }
}
