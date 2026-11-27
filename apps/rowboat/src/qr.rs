//! The invite's QR code as terminal text: two modules per character with half blocks, dark on a
//! light quiet zone of four modules, as phone cameras read from a screen.

use qrcodegen::{QrCode, QrCodeEcc};

/// The QR code of `text` (medium error correction), one line per two module rows. `None` when
/// the text is too long for any QR version.
pub fn render(text: &str) -> Option<String> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let size = code.size();
    let quiet = 4;
    let dark = |x: i32, y: i32| x >= 0 && y >= 0 && x < size && y < size && code.get_module(x, y);
    let mut out = String::new();
    let mut y = -quiet;
    while y < size + quiet {
        for x in -quiet..size + quiet {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (false, false) => '\u{2588}',
                (true, false) => '\u{2584}',
                (false, true) => '\u{2580}',
                (true, true) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_square_and_framed_by_its_quiet_zone() {
        let text = format!("peleda-pair:{}", "A".repeat(120));
        let out = render(&text).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert_eq!(lines.len(), width.div_ceil(2));
        assert!(
            lines[0].chars().all(|c| c == '\u{2588}'),
            "light top border"
        );
        assert!(lines.iter().any(|l| l.contains(' ')), "dark modules shown");
    }

    #[test]
    fn the_same_text_draws_the_same_code() {
        assert_eq!(render("peleda-pair:ABC"), render("peleda-pair:ABC"));
        assert_ne!(render("peleda-pair:ABC"), render("peleda-pair:ABD"));
        assert_eq!(render(&"x".repeat(8000)), None);
    }
}
