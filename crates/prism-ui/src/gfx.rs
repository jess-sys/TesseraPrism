//! Drawing helpers: fonts, text measuring/wrapping, rotation adapter.

use embedded_graphics::{
    pixelcolor::{Gray4, GrayColor},
    prelude::*,
    primitives::Rectangle,
    Pixel,
};
use u8g2_fonts::{
    fonts,
    types::{FontColor, HorizontalAlignment, VerticalPosition},
    FontRenderer,
};

/// Physical panel size (landscape native).
pub const PANEL_W: u32 = 960;
pub const PANEL_H: u32 = 540;

/// Logical -> physical orientation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Rotation {
    /// Logical 540x960 mapped onto the 960x540 panel (rotated 90 degrees: logical (x,y) -> panel (y, 539-x)).
    #[default]
    Portrait,
    /// Logical 960x540 == panel.
    Landscape,
}

impl Rotation {
    pub fn logical_size(self) -> Size {
        match self {
            Rotation::Portrait => Size::new(PANEL_H, PANEL_W),
            Rotation::Landscape => Size::new(PANEL_W, PANEL_H),
        }
    }
    /// Logical point -> panel point.
    pub fn to_panel(self, p: Point) -> Point {
        match self {
            Rotation::Landscape => p,
            Rotation::Portrait => Point::new(p.y, PANEL_H as i32 - 1 - p.x),
        }
    }
    /// Panel point -> logical point (use for raw touch coordinates).
    pub fn touch_to_logical(self, x: i32, y: i32) -> Point {
        match self {
            Rotation::Landscape => Point::new(x, y),
            Rotation::Portrait => Point::new(PANEL_H as i32 - 1 - y, x),
        }
    }
    /// Logical rectangle -> panel rectangle (for partial refresh).
    pub fn rect_to_panel(self, r: Rectangle) -> Rectangle {
        if r.size.width == 0 || r.size.height == 0 {
            return r;
        }
        let a = self.to_panel(r.top_left);
        let b = self.to_panel(r.top_left + Point::new(r.size.width as i32 - 1, r.size.height as i32 - 1));
        let (x0, x1) = (a.x.min(b.x), a.x.max(b.x));
        let (y0, y1) = (a.y.min(b.y), a.y.max(b.y));
        Rectangle::new(Point::new(x0, y0), Size::new((x1 - x0 + 1) as u32, (y1 - y0 + 1) as u32))
    }
}

/// DrawTarget adapter: draw in logical coordinates onto a physical 960x540 target.
pub struct Rotated<'a, D: DrawTarget<Color = Gray4>> {
    inner: &'a mut D,
    rot: Rotation,
}

impl<'a, D: DrawTarget<Color = Gray4>> Rotated<'a, D> {
    pub fn new(inner: &'a mut D, rot: Rotation) -> Self {
        Self { inner, rot }
    }
}

impl<D: DrawTarget<Color = Gray4>> OriginDimensions for Rotated<'_, D> {
    fn size(&self) -> Size {
        self.rot.logical_size()
    }
}

impl<D: DrawTarget<Color = Gray4>> DrawTarget for Rotated<'_, D> {
    type Color = Gray4;
    type Error = D::Error;
    fn draw_iter<I: IntoIterator<Item = Pixel<Gray4>>>(&mut self, pixels: I) -> Result<(), Self::Error> {
        let rot = self.rot;
        self.inner
            .draw_iter(pixels.into_iter().map(move |Pixel(p, c)| Pixel(rot.to_panel(p), c)))
    }
}

pub const INK: Gray4 = Gray4::BLACK;
pub const PAPER: Gray4 = Gray4::WHITE;
/// Secondary text.
pub const DIM: Gray4 = Gray4::new(3);
/// Separators and disabled strokes.
pub const RULE: Gray4 = Gray4::new(7);
/// Light fill (banners, bars).
pub const FILL: Gray4 = Gray4::new(12);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum F {
    Small,
    Body,
    Bold,
    Title,
    Big,
    Mono,
    Digits,
}

pub fn renderer(f: F) -> FontRenderer {
    match f {
        F::Small => FontRenderer::new::<fonts::u8g2_font_helvR18_tf>(),
        F::Body => FontRenderer::new::<fonts::u8g2_font_helvR24_tf>(),
        F::Bold => FontRenderer::new::<fonts::u8g2_font_helvB24_tf>(),
        F::Title => FontRenderer::new::<fonts::u8g2_font_fub30_tf>(),
        F::Big => FontRenderer::new::<fonts::u8g2_font_fub42_tf>(),
        F::Mono => FontRenderer::new::<fonts::u8g2_font_inb27_mf>(),
        F::Digits => FontRenderer::new::<fonts::u8g2_font_logisoso92_tn>(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
    Left,
    Center,
    Right,
}

pub fn text_width(f: F, s: &str) -> i32 {
    renderer(f)
        .get_rendered_dimensions(s, Point::zero(), VerticalPosition::Baseline)
        .ok()
        .map(|d| d.advance.x)
        .unwrap_or(0)
}

/// Draw text with (x, cy) anchor: cy is the vertical centre of the text line.
pub fn draw_text<D: DrawTarget<Color = Gray4>>(d: &mut D, s: &str, x: i32, cy: i32, f: F, a: Align, color: Gray4) {
    let h = match a {
        Align::Left => HorizontalAlignment::Left,
        Align::Center => HorizontalAlignment::Center,
        Align::Right => HorizontalAlignment::Right,
    };
    let _ = renderer(f).render_aligned(s, Point::new(x, cy), VerticalPosition::Center, h, FontColor::Transparent(color), d);
}

/// Truncate with "..." so that it fits max_w.
pub fn fit(f: F, s: &str, max_w: i32) -> String {
    if text_width(f, s) <= max_w {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let mut n = chars.len();
    while n > 0 {
        let cand: String = chars[..n].iter().collect::<String>() + "...";
        if text_width(f, &cand) <= max_w {
            return cand;
        }
        n -= 1;
    }
    String::new()
}

/// Greedy word wrap (breaks long words by char), at most `max_lines` lines (last one truncated).
pub fn wrap(f: F, s: &str, max_w: i32, max_lines: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in s.split_whitespace() {
        let cand = if cur.is_empty() { word.to_string() } else { format!("{cur} {word}") };
        if text_width(f, &cand) <= max_w {
            cur = cand;
        } else {
            if !cur.is_empty() {
                lines.push(core::mem::take(&mut cur));
            }
            // break very long word
            let mut w = word.to_string();
            while text_width(f, &w) > max_w {
                let mut n = w.chars().count();
                while n > 1 && text_width(f, &w.chars().take(n).collect::<String>()) > max_w {
                    n -= 1;
                }
                lines.push(w.chars().take(n).collect());
                w = w.chars().skip(n).collect();
            }
            cur = w;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.len() > max_lines {
        lines.truncate(max_lines);
        let last = lines.pop().unwrap();
        lines.push(fit(f, &(last + "..."), max_w));
    }
    lines
}

pub fn fill<D: DrawTarget<Color = Gray4>>(d: &mut D, r: Rectangle, c: Gray4) {
    let _ = d.fill_solid(&r, c);
}

/// Stroke rectangle inside `r` with thickness `t`.
pub fn stroke<D: DrawTarget<Color = Gray4>>(d: &mut D, r: Rectangle, t: u32, c: Gray4) {
    let (x, y, w, h) = (r.top_left.x, r.top_left.y, r.size.width, r.size.height);
    let t = t.min(w / 2).min(h / 2);
    fill(d, Rectangle::new(Point::new(x, y), Size::new(w, t)), c);
    fill(d, Rectangle::new(Point::new(x, y + h as i32 - t as i32), Size::new(w, t)), c);
    fill(d, Rectangle::new(Point::new(x, y), Size::new(t, h)), c);
    fill(d, Rectangle::new(Point::new(x + w as i32 - t as i32, y), Size::new(t, h)), c);
}

pub fn union(a: Rectangle, b: Rectangle) -> Rectangle {
    if a.size.width == 0 || a.size.height == 0 {
        return b;
    }
    if b.size.width == 0 || b.size.height == 0 {
        return a;
    }
    let x0 = a.top_left.x.min(b.top_left.x);
    let y0 = a.top_left.y.min(b.top_left.y);
    let x1 = (a.top_left.x + a.size.width as i32).max(b.top_left.x + b.size.width as i32);
    let y1 = (a.top_left.y + a.size.height as i32).max(b.top_left.y + b.size.height as i32);
    Rectangle::new(Point::new(x0, y0), Size::new((x1 - x0) as u32, (y1 - y0) as u32))
}

pub fn rect(x: i32, y: i32, w: u32, h: u32) -> Rectangle {
    Rectangle::new(Point::new(x, y), Size::new(w, h))
}
