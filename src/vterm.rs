//! Emulador de terminal xterm (crate vt100) + renderização em egui + teclado.
//! Suporta aplicações de tela cheia: nano, vim, htop, mc, menus de switch etc.

use eframe::egui::{self, Color32, Event, FontId, Key, Modifiers, Pos2, Rect, Sense, Stroke, Vec2};
use std::num::NonZeroU16;

const DEFAULT_FG: Color32 = Color32::from_rgb(205, 214, 222);
const DEFAULT_BG: Color32 = Color32::from_rgb(14, 16, 20);
const PAD: f32 = 6.0;

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v.max(1)).unwrap()
}

pub struct VTerm {
    parser: vt100::Parser,
    id: egui::Id,
}

pub struct TermOutput {
    /// Bytes a enviar ao servidor (teclas digitadas).
    pub input: Vec<u8>,
    /// Novo tamanho (cols, rows) se a área mudou.
    pub resized: Option<(u16, u16)>,
}

impl VTerm {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            parser: vt100::Parser::new(nz(rows), nz(cols), 5000),
            id: egui::Id::new("vterm"),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        let (r, c) = self.parser.screen().size();
        (c.get(), r.get())
    }

    pub fn process(&mut self, data: &str) {
        self.parser.process(data.as_bytes());
    }

    pub fn clear(&mut self) {
        let (c, r) = self.size();
        self.parser = vt100::Parser::new(nz(r), nz(c), 5000);
    }

    pub fn screen_text(&self) -> String {
        self.parser.screen().contents()
    }

    pub fn request_focus(&self, ctx: &egui::Context) {
        ctx.memory_mut(|m| m.request_focus(self.id));
    }

    /// Desenha o terminal ocupando todo o espaço disponível e captura o teclado
    /// quando focado. `enabled` = sessão conectada.
    pub fn show(&mut self, ui: &mut egui::Ui, enabled: bool) -> TermOutput {
        let mut out = TermOutput { input: Vec::new(), resized: None };
        let font = FontId::monospace(13.5);
        let (cw, rh) = ui.fonts(|f| (f.glyph_width(&font, 'M'), f.row_height(&font)));

        let rect = ui.available_rect_before_wrap();
        let resp = ui.interact(rect, self.id, Sense::click());
        ui.advance_cursor_after_rect(rect);
        if resp.clicked() {
            resp.request_focus();
        }
        let focused = resp.has_focus();

        // ---- tamanho ----
        let cols = (((rect.width() - 2.0 * PAD) / cw).floor() as u16).clamp(20, 500);
        let rows = (((rect.height() - 2.0 * PAD) / rh).floor() as u16).clamp(5, 300);
        if (cols, rows) != self.size() {
            self.parser.set_size(nz(rows), nz(cols));
            out.resized = Some((cols, rows));
        }

        // ---- teclado ----
        if focused && enabled {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    self.id,
                    egui::EventFilter {
                        tab: true,
                        horizontal_arrows: true,
                        vertical_arrows: true,
                        escape: true,
                    },
                )
            });
            let screen = self.parser.screen();
            let (app_cursor, paste_br) = (screen.application_cursor(), screen.bracketed_paste());
            let events = ui.input(|i| i.events.clone());
            for ev in &events {
                if let Some(b) = encode_event(ev, app_cursor, paste_br) {
                    out.input.extend_from_slice(&b);
                }
            }
            if !out.input.is_empty() {
                self.parser.screen_mut().set_scrollback(0);
            }
        }

        // ---- rolagem (histórico) ----
        if resp.hovered() && !self.parser.screen().alternate_screen() {
            let dy = ui.input(|i| i.raw_scroll_delta.y);
            if dy.abs() > 0.0 {
                let cur = self.parser.screen().scrollback() as i64;
                let lines = (dy / rh * 1.5).round() as i64;
                let next = (cur + lines).max(0) as usize;
                self.parser.screen_mut().set_scrollback(next);
            }
        }

        // ---- desenho ----
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 4.0, DEFAULT_BG);
        if focused {
            painter.rect_stroke(rect, 4.0, Stroke::new(1.0_f32, Color32::from_rgb(60, 110, 170)), egui::StrokeKind::Inside);
        }
        let origin = rect.min + Vec2::splat(PAD);
        let screen = self.parser.screen();
        let (srows, scols) = (screen.size().0.get(), screen.size().1.get());

        for r in 0..srows {
            let y = origin.y + r as f32 * rh;
            let mut c = 0u16;
            while c < scols {
                let Some(cell) = screen.cell(r, c) else { break };
                if cell.is_wide_continuation() {
                    c += 1;
                    continue;
                }
                let (fg, bg) = cell_colors(cell);
                let attrs = (fg, bg, cell.underline());
                // agrupa células ASCII contíguas com os mesmos atributos
                let start = c;
                let mut text = String::new();
                let first = cell.contents();
                let ascii_run = first.is_empty() || first.is_ascii();
                text.push_str(if first.is_empty() { " " } else { first });
                c += if cell.is_wide() { 2 } else { 1 };
                if ascii_run {
                    while c < scols {
                        let Some(n) = screen.cell(r, c) else { break };
                        let s = n.contents();
                        let (nfg, nbg) = cell_colors(n);
                        if n.is_wide() || !(s.is_empty() || s.is_ascii()) || (nfg, nbg, n.underline()) != attrs {
                            break;
                        }
                        text.push_str(if s.is_empty() { " " } else { s });
                        c += 1;
                    }
                }
                let width_cells = c - start;
                let pos = Pos2::new(origin.x + start as f32 * cw, y);
                if bg != DEFAULT_BG {
                    painter.rect_filled(Rect::from_min_size(pos, Vec2::new(width_cells as f32 * cw, rh)), 0.0, bg);
                }
                if text.trim().is_empty() {
                    continue;
                }
                painter.text(pos, egui::Align2::LEFT_TOP, &text, font.clone(), fg);
                if attrs.2 {
                    let uy = y + rh - 1.5;
                    painter.line_segment(
                        [Pos2::new(pos.x, uy), Pos2::new(pos.x + width_cells as f32 * cw, uy)],
                        Stroke::new(1.0_f32, fg),
                    );
                }
            }
        }

        // cursor
        if enabled && !screen.hide_cursor() && screen.scrollback() == 0 {
            let (cr, cc) = screen.cursor_position();
            let cur = Rect::from_min_size(
                Pos2::new(origin.x + cc as f32 * cw, origin.y + cr as f32 * rh),
                Vec2::new(cw, rh),
            );
            if focused {
                painter.rect_filled(cur, 0.0, Color32::from_rgba_unmultiplied(205, 214, 222, 150));
            } else {
                painter.rect_stroke(cur, 0.0, Stroke::new(1.0_f32, DEFAULT_FG), egui::StrokeKind::Inside);
            }
        }

        if screen.scrollback() > 0 {
            painter.text(
                rect.right_top() + Vec2::new(-10.0, 6.0),
                egui::Align2::RIGHT_TOP,
                format!("↑ histórico ({} linhas) — role para baixo ou tecle para voltar", screen.scrollback()),
                FontId::proportional(12.0),
                Color32::from_rgb(230, 180, 60),
            );
        }
        if !focused && enabled {
            painter.text(
                rect.right_bottom() + Vec2::new(-10.0, -6.0),
                egui::Align2::RIGHT_BOTTOM,
                "clique no terminal para digitar direto (nano, vim, htop…)",
                FontId::proportional(11.5),
                Color32::from_gray(120),
            );
        }
        out
    }
}

// ---------------- cores ----------------

fn idx_color(i: u8) -> Color32 {
    const BASE: [(u8, u8, u8); 16] = [
        (0, 0, 0), (205, 49, 49), (13, 188, 121), (229, 229, 16),
        (36, 114, 200), (188, 63, 188), (17, 168, 205), (229, 229, 229),
        (102, 102, 102), (241, 76, 76), (35, 209, 139), (245, 245, 67),
        (59, 142, 234), (214, 112, 214), (41, 184, 219), (255, 255, 255),
    ];
    match i {
        0..=15 => {
            let (r, g, b) = BASE[i as usize];
            Color32::from_rgb(r, g, b)
        }
        16..=231 => {
            let n = i - 16;
            let lv = |v: u8| if v == 0 { 0 } else { 55 + v * 40 };
            Color32::from_rgb(lv(n / 36), lv((n / 6) % 6), lv(n % 6))
        }
        _ => {
            let g = 8 + (i - 232) * 10;
            Color32::from_rgb(g, g, g)
        }
    }
}

fn cell_colors(cell: &vt100::Cell) -> (Color32, Color32) {
    let mut fg = match cell.fgcolor() {
        vt100::Color::Default => DEFAULT_FG,
        vt100::Color::Idx(i) if cell.bold() && i < 8 => idx_color(i + 8),
        vt100::Color::Idx(i) => idx_color(i),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    };
    if cell.bold() && cell.fgcolor() == vt100::Color::Default {
        fg = Color32::WHITE;
    }
    let mut bg = match cell.bgcolor() {
        vt100::Color::Default => DEFAULT_BG,
        vt100::Color::Idx(i) => idx_color(i),
        vt100::Color::Rgb(r, g, b) => Color32::from_rgb(r, g, b),
    };
    if cell.dim() {
        fg = fg.gamma_multiply(0.6);
    }
    if cell.inverse() {
        std::mem::swap(&mut fg, &mut bg);
    }
    (fg, bg)
}

// ---------------- teclado ----------------

fn encode_event(ev: &Event, app_cursor: bool, bracketed: bool) -> Option<Vec<u8>> {
    match ev {
        Event::Text(t) => Some(t.as_bytes().to_vec()),
        Event::Copy => Some(vec![0x03]), // Ctrl+C
        Event::Cut => Some(vec![0x18]),  // Ctrl+X (sair do nano)
        Event::Paste(t) => {
            let t = t.replace("\r\n", "\r").replace('\n', "\r");
            Some(if bracketed {
                format!("\x1b[200~{t}\x1b[201~").into_bytes()
            } else {
                t.into_bytes()
            })
        }
        Event::Key { key, pressed: true, modifiers, .. } => encode_key(*key, *modifiers, app_cursor),
        _ => None,
    }
}

fn encode_key(key: Key, m: Modifiers, app_cursor: bool) -> Option<Vec<u8>> {
    let s = |x: &str| Some(x.as_bytes().to_vec());
    let arrow = |c: char| {
        if m.ctrl {
            Some(format!("\x1b[1;5{c}").into_bytes())
        } else if m.shift {
            Some(format!("\x1b[1;2{c}").into_bytes())
        } else if app_cursor {
            Some(format!("\x1bO{c}").into_bytes())
        } else {
            Some(format!("\x1b[{c}").into_bytes())
        }
    };
    match key {
        Key::Enter => return s("\r"),
        Key::Backspace => return s("\x7f"),
        Key::Tab if m.shift => return s("\x1b[Z"),
        Key::Tab => return s("\t"),
        Key::Escape => return s("\x1b"),
        Key::ArrowUp => return arrow('A'),
        Key::ArrowDown => return arrow('B'),
        Key::ArrowRight => return arrow('C'),
        Key::ArrowLeft => return arrow('D'),
        Key::Home => return s("\x1b[H"),
        Key::End => return s("\x1b[F"),
        Key::PageUp => return s("\x1b[5~"),
        Key::PageDown => return s("\x1b[6~"),
        Key::Insert => return s("\x1b[2~"),
        Key::Delete => return s("\x1b[3~"),
        Key::F1 => return s("\x1bOP"),
        Key::F2 => return s("\x1bOQ"),
        Key::F3 => return s("\x1bOR"),
        Key::F4 => return s("\x1bOS"),
        Key::F5 => return s("\x1b[15~"),
        Key::F6 => return s("\x1b[17~"),
        Key::F7 => return s("\x1b[18~"),
        Key::F8 => return s("\x1b[19~"),
        Key::F9 => return s("\x1b[20~"),
        Key::F10 => return s("\x1b[21~"),
        Key::F11 => return s("\x1b[23~"),
        Key::F12 => return s("\x1b[24~"),
        _ => {}
    }
    let name = key.name();
    let ch = if name.chars().count() == 1 { name.chars().next() } else { None };
    if m.ctrl && !m.alt {
        return match (key, ch) {
            (Key::Space, _) => Some(vec![0]),
            (Key::OpenBracket, _) => Some(vec![0x1b]),
            (Key::Backslash, _) => Some(vec![0x1c]),
            (Key::CloseBracket, _) => Some(vec![0x1d]),
            (Key::Slash, _) => Some(vec![0x1f]),
            (_, Some(c)) if c.is_ascii_alphabetic() => {
                Some(vec![(c.to_ascii_uppercase() as u8) - b'A' + 1])
            }
            _ => None,
        };
    }
    if m.alt && !m.ctrl {
        if let Some(c) = ch {
            let c = if m.shift { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() };
            return Some(format!("\x1b{c}").into_bytes());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_keys() {
        let ctrl = Modifiers { ctrl: true, ..Default::default() };
        assert_eq!(encode_key(Key::O, ctrl, false), Some(vec![0x0f])); // ^O salvar nano
        assert_eq!(encode_key(Key::W, ctrl, false), Some(vec![0x17]));
        assert_eq!(encode_key(Key::ArrowUp, Modifiers::default(), true), Some(b"\x1bOA".to_vec()));
    }

    #[test]
    fn full_screen_app_render_state() {
        let mut t = VTerm::new(80, 24);
        // nano-like: tela alternativa, posiciona cursor, texto invertido
        t.process("\x1b[?1049h\x1b[H\x1b[7m  GNU nano 8.4  \x1b[0m\x1b[24;1H\x1b[7m^G\x1b[0m Help");
        let s = t.parser.screen();
        assert!(s.alternate_screen());
        assert_eq!(s.cell(0, 2).unwrap().contents(), "G");
        assert!(s.cell(0, 2).unwrap().inverse());
        assert!(s.contents().contains("^G Help"));
    }
}
