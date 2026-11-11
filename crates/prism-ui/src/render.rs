//! Drawing of layout items.

use crate::gfx::*;
use crate::layout::*;
use crate::ui::{Status, Ui};
use embedded_graphics::{
    pixelcolor::Gray4,
    prelude::*,
    primitives::{Circle, Line, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, Triangle},
};
use u8g2_fonts::types::{FontColor, HorizontalAlignment, VerticalPosition};

pub fn draw_ui<D: DrawTarget<Color = Gray4>>(ui: &Ui, d: &mut D) {
    let sz = ui.size();
    let _ = d.fill_solid(&Rectangle::new(Point::zero(), sz), PAPER);
    let backdrop = ui.backdrop_items();
    if !backdrop.is_empty() {
        draw_items(d, &backdrop, None, false);
        // dim backdrop with a light checker-free overlay: lighten by drawing nothing; the card has a thick border
    }
    draw_items(d, &ui.items(), ui.pressed, false);
}

fn map(c: Gray4, inv: bool) -> Gray4 {
    if inv {
        Gray4::new(15 - c.luma())
    } else {
        c
    }
}

pub fn draw_items<D: DrawTarget<Color = Gray4>>(d: &mut D, items: &[Item], pressed: Option<Id>, inv: bool) {
    for it in items {
        draw_item(d, it, pressed, inv);
    }
}

fn draw_item<D: DrawTarget<Color = Gray4>>(d: &mut D, it: &Item, pressed: Option<Id>, inv: bool) {
    match it {
        Item::Btn(b) => draw_btn(d, b, pressed == Some(b.id)),
        Item::Text { s, x, cy, font, align, color } => draw_text(d, s, *x, *cy, *font, *align, map(*color, inv)),
        Item::Fill { rect, color } => fill(d, *rect, map(*color, inv)),
        Item::Frame { rect, fill: f, border } => {
            if let Some(c) = f {
                fill(d, *rect, map(*c, inv));
            }
            stroke(d, *rect, *border, map(INK, inv));
        }
        Item::Icon { kind, rect } => draw_icon(d, *kind, *rect, map(INK, inv), map(PAPER, inv)),
        Item::Dots { cx, cy, total, filled } => {
            let pitch = 40;
            let x0 = cx - (*total as i32 - 1) * pitch / 2;
            for i in 0..*total {
                let c = Point::new(x0 + i as i32 * pitch, *cy);
                if i < *filled {
                    let _ = Circle::with_center(c, 28).into_styled(PrimitiveStyle::with_fill(INK)).draw(d);
                } else {
                    // Black, not grey: PIN dots are refreshed with DU, which only drives black/white.
                    let _ = Circle::with_center(c, 20)
                        .into_styled(PrimitiveStyleBuilder::new().stroke_color(INK).stroke_width(2).build())
                        .draw(d);
                }
            }
        }
        Item::Bar { rect: r, segs, filled } => {
            let gap = 6;
            let sw = (r.size.width as i32 - gap * (*segs as i32 - 1)) / *segs as i32;
            for i in 0..*segs {
                let sr = Rectangle::new(r.top_left + Point::new(i as i32 * (sw + gap), 0), Size::new(sw as u32, r.size.height));
                if i < *filled {
                    fill(d, sr, INK);
                } else {
                    stroke(d, sr, 3, RULE);
                }
            }
        }
        Item::Digits { s, cx, cy, font, split } => draw_digits(d, s, *cx, *cy, *font, *split, map(INK, inv)),
        Item::Brand { cx, cy, large, inverted } => draw_brand(d, *cx, *cy, *large, *inverted),
        Item::IconC { kind, rect, fg, bg } => draw_icon(d, *kind, *rect, *fg, *bg),
        Item::Battery { x, cy, pct, fg, bg } => draw_battery(d, *x, *cy, *pct, *fg, *bg),
        Item::Status(st) => draw_status(d, st),
    }
}

fn draw_digits<D: DrawTarget<Color = Gray4>>(d: &mut D, s: &str, cx: i32, cy: i32, font: F, split: usize, color: Gray4) {
    let pitch = text_width(font, "0") + 10;
    let group_gap = 44;
    let n = s.chars().count() as i32;
    let total = n * pitch + if split > 0 && (split as i32) < n { group_gap } else { 0 };
    let mut x = cx - total / 2;
    for (i, ch) in s.chars().enumerate() {
        if i == split && split > 0 {
            x += group_gap;
        }
        let cw = text_width(font, &ch.to_string());
        draw_text(d, &ch.to_string(), x + (pitch - cw) / 2, cy, font, Align::Left, color);
        x += pitch;
    }
}

fn draw_btn<D: DrawTarget<Color = Gray4>>(d: &mut D, b: &Btn, pressed: bool) {
    // base look
    let (mut bg, mut fg, border): (Gray4, Gray4, Option<(u32, Gray4)>) = match b.style {
        Style::Primary => (INK, PAPER, None),
        Style::Outline => (PAPER, INK, Some((3, INK))),
        Style::Tile => (PAPER, INK, Some((4, INK))),
        Style::Row => (PAPER, INK, None),
        Style::Seg(true) => (INK, PAPER, None),
        Style::Seg(false) => (PAPER, INK, Some((3, INK))),
    };
    let mut border = border;
    if !b.enabled {
        bg = PAPER;
        fg = RULE;
        border = Some((3, RULE));
        if b.style == Style::Row {
            border = None;
        }
    }
    let inv = pressed && b.enabled;
    if inv {
        core::mem::swap(&mut bg, &mut fg);
        if let Some((t, _)) = border {
            border = Some((t, fg));
        } else if b.style != Style::Row {
            border = Some((3, INK));
        }
    }
    fill(d, b.rect, bg);
    if let Some((t, c)) = border {
        // pressed buttons keep a border in the (new) background colour to stay crisp
        stroke(d, b.rect, t, if inv { bg } else { c });
        if inv {
            stroke(d, b.rect, t, INK);
        }
    }
    if b.style == Style::Row && !inv {
        fill(d, rect(b.rect.top_left.x + 8, b.rect.top_left.y + b.rect.size.height as i32 - 2, b.rect.size.width - 16, 2), RULE);
    }
    // inner items drawn with colours mapped for inversion
    let tone_inv = inv || (b.style == Style::Primary && false);
    for it in &b.inner {
        draw_item(d, it, None, tone_inv);
    }
    // label + icon
    let c = b.rect.center();
    let icon_w = if b.icon.is_some() { 30 } else { 0 };
    let lw = if b.label.is_empty() { 0 } else { text_width(b.font, &b.label) };
    let gap = if lw > 0 && icon_w > 0 { 14 } else { 0 };
    let total = lw + gap + icon_w;
    let mut x = c.x - total / 2;
    let label_fit = if b.label.is_empty() { String::new() } else { fit(b.font, &b.label, b.rect.size.width as i32 - 8) };
    if let Some(ic) = b.icon {
        let (ix, tx) = match ic {
            Icon::Right => (x + lw + gap, x),
            _ => (x, x + icon_w + gap),
        };
        draw_icon(d, ic, Rectangle::new(Point::new(ix, c.y - 15), Size::new(30, 30)), fg, bg);
        x = tx;
    }
    if lw > 0 {
        draw_text(d, &label_fit, x, c.y, b.font, Align::Left, fg);
    }
}

fn line<D: DrawTarget<Color = Gray4>>(d: &mut D, a: Point, b: Point, w: u32, c: Gray4) {
    let _ = Line::new(a, b).into_styled(PrimitiveStyle::with_stroke(c, w)).draw(d);
}

fn disc<D: DrawTarget<Color = Gray4>>(d: &mut D, c: Point, diam: u32, col: Gray4) {
    let _ = Circle::with_center(c, diam).into_styled(PrimitiveStyle::with_fill(col)).draw(d);
}

fn ring<D: DrawTarget<Color = Gray4>>(d: &mut D, c: Point, diam: u32, t: u32, col: Gray4) {
    let _ = Circle::with_center(c, diam)
        .into_styled(PrimitiveStyleBuilder::new().stroke_color(col).stroke_width(t).build())
        .draw(d);
}

pub fn draw_icon<D: DrawTarget<Color = Gray4>>(d: &mut D, kind: Icon, r: Rectangle, fg: Gray4, bg: Gray4) {
    let s = r.size.width.min(r.size.height) as i32;
    let o = r.top_left;
    let c = Point::new(o.x + s / 2, o.y + s / 2);
    let p = |fx: i32, fy: i32| Point::new(o.x + s * fx / 100, o.y + s * fy / 100);
    let t = (s as u32 / 10).max(3);
    match kind {
        Icon::Left => {
            let _ = Triangle::new(p(80, 10), p(80, 90), p(15, 50)).into_styled(PrimitiveStyle::with_fill(fg)).draw(d);
        }
        Icon::Right => {
            let _ = Triangle::new(p(20, 10), p(20, 90), p(85, 50)).into_styled(PrimitiveStyle::with_fill(fg)).draw(d);
        }
        Icon::Chevron => {
            line(d, p(30, 10), p(75, 50), 5, fg);
            line(d, p(75, 50), p(30, 90), 5, fg);
        }
        Icon::Key => {
            ring(d, p(28, 50), (s * 40 / 100) as u32, t, fg);
            fill(d, Rectangle::new(p(46, 50) - Point::new(0, t as i32 / 2), Size::new((s * 46 / 100) as u32, t)), fg);
            fill(d, Rectangle::new(p(78, 50), Size::new(t, (s * 22 / 100) as u32)), fg);
            fill(d, Rectangle::new(p(62, 50), Size::new(t, (s * 16 / 100) as u32)), fg);
        }
        Icon::Clock => {
            ring(d, c, (s * 90 / 100) as u32, t, fg);
            line(d, c, p(50, 22), t, fg);
            line(d, c, p(70, 58), t, fg);
        }
        Icon::Passkey => {
            disc(d, p(42, 32), (s * 36 / 100) as u32, fg);
            disc(d, p(42, 90), (s * 64 / 100) as u32, fg);
            fill(d, Rectangle::new(p(0, 100), Size::new(s as u32, (s * 30 / 100) as u32)), bg);
            // little key mark
            ring(d, p(80, 66), (s * 18 / 100) as u32, 3, fg);
            fill(d, Rectangle::new(p(80, 72), Size::new(3, (s * 24 / 100) as u32)), fg);
        }
        Icon::Ssh => {
            line(d, p(10, 25), p(42, 50), t, fg);
            line(d, p(42, 50), p(10, 75), t, fg);
            fill(d, Rectangle::new(p(52, 76), Size::new((s * 38 / 100) as u32, t)), fg);
        }
        Icon::Codes => {
            for i in 0..4 {
                let y = 12 + i * 24;
                fill(d, Rectangle::new(p(6, y), Size::new((s * 12 / 100).max(4) as u32, (s * 12 / 100).max(4) as u32)), fg);
                fill(d, Rectangle::new(p(28, y), Size::new((s * 64 / 100) as u32, (s * 12 / 100).max(4) as u32)), fg);
            }
        }
        Icon::Gear => {
            let dirs: [(i32, i32); 8] = [(100, 0), (71, 71), (0, 100), (-71, 71), (-100, 0), (-71, -71), (0, -100), (71, -71)];
            for (dx, dy) in dirs {
                let a = Point::new(c.x + dx * s * 30 / 10000, c.y + dy * s * 30 / 10000);
                let b = Point::new(c.x + dx * s * 47 / 10000, c.y + dy * s * 47 / 10000);
                line(d, a, b, (t * 2).min(14), fg);
            }
            disc(d, c, (s * 66 / 100) as u32, fg);
            disc(d, c, (s * 28 / 100) as u32, bg);
        }
        Icon::Lock => {
            fill(d, Rectangle::new(p(15, 45), Size::new((s * 70 / 100) as u32, (s * 50 / 100) as u32)), fg);
            ring(d, p(50, 32), (s * 46 / 100) as u32, t, fg);
            fill(d, Rectangle::new(p(0, 40), Size::new(s as u32, (s * 8 / 100).max(2) as u32)), bg);
            fill(d, Rectangle::new(p(15, 45), Size::new((s * 70 / 100) as u32, (s * 50 / 100) as u32)), fg);
            disc(d, p(50, 68), (s * 12 / 100).max(3) as u32, bg);
        }
        Icon::Shield => {
            let _ = Triangle::new(p(10, 25), p(90, 25), p(50, 95)).into_styled(PrimitiveStyle::with_fill(fg)).draw(d);
            fill(d, Rectangle::new(p(10, 10), Size::new((s * 80 / 100) as u32, (s * 25 / 100) as u32)), fg);
            line(d, p(32, 40), p(46, 56), t, bg);
            line(d, p(46, 56), p(70, 30), t, bg);
        }
        Icon::Arrow => {
            line(d, p(5, 50), p(70, 50), t, fg);
            let _ = Triangle::new(p(58, 20), p(58, 80), p(98, 50)).into_styled(PrimitiveStyle::with_fill(fg)).draw(d);
        }
        Icon::Power => {
            ring(d, p(50, 55), (s * 70 / 100) as u32, t, fg);
            fill(d, Rectangle::new(p(0, 0), Size::new(s as u32, (s * 40 / 100) as u32)).intersection(&Rectangle::new(p(38, 0), Size::new((s * 24 / 100) as u32, (s * 40 / 100) as u32))), bg);
            line(d, p(50, 8), p(50, 52), t, fg);
        }
    }
}

const BRAND_480: &[u8] = include_bytes!("../assets/neutheria-systems-480x30.gray4");
const BRAND_360: &[u8] = include_bytes!("../assets/neutheria-systems-360x22.gray4");

/// Neutheria Systems wordmark (pre-rendered Gray4 bitmap, see `examples/gen_logo.rs`).
pub fn draw_brand<D: DrawTarget<Color = Gray4>>(d: &mut D, cx: i32, cy: i32, large: bool, inverted: bool) {
    use embedded_graphics::image::{GetPixel, ImageRaw};
    let (data, w, h) = if large { (BRAND_480, 480u32, 30u32) } else { (BRAND_360, 360, 22) };
    let raw: ImageRaw<Gray4> = ImageRaw::new(data, w);
    let (x0, y0) = (cx - w as i32 / 2, cy - h as i32 / 2);
    let px = (0..h).flat_map(|y| (0..w).map(move |x| (x, y))).filter_map(|(x, y)| {
        let c = raw.pixel(Point::new(x as i32, y as i32))?;
        let c = if inverted { Gray4::new(15 - c.luma()) } else { c };
        Some(Pixel(Point::new(x0 + x as i32, y0 + y as i32), c))
    });
    let _ = d.draw_iter(px);
}

/// Battery gauge 46x22 (left edge x, centred on cy).
pub fn draw_battery<D: DrawTarget<Color = Gray4>>(d: &mut D, x: i32, cy: i32, pct: u8, fg: Gray4, bg: Gray4) {
    let y = cy - 11;
    stroke(d, rect(x, y, 42, 22), 3, fg);
    fill(d, rect(x + 42, y + 6, 4, 10), fg);
    fill(d, rect(x + 3, y + 3, 36, 16), bg);
    let inner = (34 * pct.min(100) as i32 / 100) as u32;
    fill(d, rect(x + 4, y + 4, inner, 14), fg);
}

fn draw_status<D: DrawTarget<Color = Gray4>>(d: &mut D, st: &Status) {
    let w = d.bounding_box().size.width as i32;
    fill(d, rect(0, STATUS_H - 2, w as u32, 2), INK);
    draw_text(d, &status_time(st), 16, 24, F::Bold, Align::Left, INK);
    if st.locked {
        draw_icon(d, Icon::Lock, rect(120, 11, 26, 26), INK, PAPER);
    }
    // right to left
    let mut x = w - 16;
    // battery body 46x22
    let bx = x - 46;
    stroke(d, rect(bx, 13, 42, 22), 3, INK);
    fill(d, rect(bx + 42, 19, 4, 10), INK);
    let inner = (34 * st.battery.min(100) as i32 / 100) as u32;
    fill(d, rect(bx + 4, 17, inner, 14), INK);
    x = bx - 8;
    let pct = format!("{}%", st.battery.min(100));
    draw_text(d, &pct, x, 24, F::Small, Align::Right, INK);
    x -= text_width(F::Small, &pct) + 10;
    if st.charging {
        // lightning bolt
        let _ = Triangle::new(Point::new(x - 4, 10), Point::new(x - 16, 28), Point::new(x - 6, 28)).into_styled(PrimitiveStyle::with_fill(INK)).draw(d);
        let _ = Triangle::new(Point::new(x - 8, 24), Point::new(x - 2, 24), Point::new(x - 14, 40)).into_styled(PrimitiveStyle::with_fill(INK)).draw(d);
        x -= 26;
    }
    for (on, label, wd) in [(st.ble, "BT", 44), (st.usb, "USB", 58)] {
        if on {
            let r = rect(x - wd, 9, wd as u32, 30);
            fill(d, r, INK);
            let _ = renderer(F::Small).render_aligned(
                label,
                r.center(),
                VerticalPosition::Center,
                HorizontalAlignment::Center,
                FontColor::Transparent(PAPER),
                d,
            );
            x -= wd + 8;
        }
    }
}
