//! Regenerate the embedded brand bitmaps from `assets/neutheria-systems.png`:
//! `cargo run -p prism-ui --example gen_logo`
//! Output: packed Gray4 (2 px/byte, first pixel in the high nibble, rows padded to a byte) as
//! expected by `embedded_graphics::image::ImageRaw<Gray4>`.
fn main() {
    let src = image::open("assets/neutheria-systems.png").expect("open logo").to_rgba8();
    for w in [480u32, 360] {
        let h = (src.height() as f32 * w as f32 / src.width() as f32).round() as u32;
        let r = image::imageops::resize(&src, w, h, image::imageops::FilterType::Lanczos3);
        let mut out = Vec::new();
        for y in 0..h {
            let mut byte = 0u8;
            for x in 0..w {
                let p = r.get_pixel(x, y);
                let a = p[3] as f32 / 255.0;
                let lum = (0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32) / 255.0;
                // Composite over white paper.
                let v = 1.0 - a * (1.0 - lum);
                let g = (v * 15.0).round().clamp(0.0, 15.0) as u8;
                if x % 2 == 0 {
                    byte = g << 4;
                } else {
                    out.push(byte | g);
                }
            }
            if w % 2 == 1 {
                out.push(byte);
            }
        }
        let path = format!("assets/neutheria-systems-{w}x{h}.gray4");
        std::fs::write(&path, &out).expect("write");
        println!("{path}: {w}x{h}, {} bytes", out.len());
    }
}
