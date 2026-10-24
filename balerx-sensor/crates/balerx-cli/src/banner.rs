//! First-run Balerx Gate banner for `balerx setup`.
//!
//! The dragon is the site favicon: a gate with the head cut out of the brand red.
//! The wordmark uses the web theme, `#8e1024` to `#b0122e`, with a lighter tint of that red.
//! Width comes from `COLUMNS`, then `terminal_size`. On Windows, block glyphs are
//! used for Windows Terminal, VS Code, and `ConEmu`.

use std::io::{self, IsTerminal, Write};

const WIDE_COLUMNS: usize = 70;
const VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const TAGLINE: &str = "Security for AI agents";
const DRAGON_WIDTH: usize = 18;
const WORD_WIDTH: usize = 31;

const DARK: Rgb = (142, 16, 36);
const BRAND: Rgb = (176, 18, 46);
const LIGHT: Rgb = (212, 72, 96);
const MUTED: Rgb = (168, 132, 138);

/// Favicon sampled into half-blocks. Each row is [`DRAGON_WIDTH`] characters.
const DRAGON: &[&str] = &[
    "        ▄██▄      ",
    "      ▄██████▄    ",
    "    ▄██████████▄  ",
    "  ▄███▀▀  ▀▀████▄ ",
    " █████      ▀████ ",
    " ████        ▀███ ",
    " ███▀       ▄████ ",
    " ███          ▀██ ",
    " ███     ▄█▄   ██ ",
    " ███     ▀███▄▄██ ",
    " ███       ██████ ",
    "████        ██████",
];

type Rgb = (u8, u8, u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerColor {
    None,
    Ansi256,
    Truecolor,
}

#[derive(Debug, Clone, Copy)]
pub struct BannerStyle {
    pub color: BannerColor,
    pub columns: usize,
    pub unicode: bool,
}

pub fn print_for_setup(no_color: bool) {
    let tty = io::stdout().is_terminal();
    let style = BannerStyle {
        color: color_mode(no_color, tty),
        columns: columns(tty),
        unicode: tty && unicode_blocks_ok(),
    };
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", render(style));
}

pub fn render(style: BannerStyle) -> String {
    if style.columns < WIDE_COLUMNS {
        return compact(style);
    }
    if style.color == BannerColor::None || !style.unicode {
        return plain_wide(style.color);
    }
    wide_art(style.color)
}

fn color_mode(no_color: bool, tty: bool) -> BannerColor {
    if no_color || !tty {
        return BannerColor::None;
    }
    match std::env::var("COLORTERM").ok().as_deref() {
        Some("truecolor" | "24bit") => BannerColor::Truecolor,
        _ => BannerColor::Ansi256,
    }
}

fn columns(tty: bool) -> usize {
    if let Some(width) = env_columns() {
        return width;
    }
    if tty {
        if let Some(width) = console_columns() {
            return width;
        }
    }
    80
}

fn console_columns() -> Option<usize> {
    let (terminal_size::Width(columns), _) = terminal_size::terminal_size()?;
    let columns = usize::from(columns);
    (columns > 0).then_some(columns)
}

fn env_columns() -> Option<usize> {
    let raw = std::env::var("COLUMNS").ok()?;
    let width = raw.trim().parse::<usize>().ok()?;
    (width > 0).then_some(width)
}

#[cfg(windows)]
fn unicode_blocks_ok() -> bool {
    windows_unicode_host()
}

#[cfg(not(windows))]
fn unicode_blocks_ok() -> bool {
    true
}

/// Windows Terminal, VS Code, and `ConEmu` can show the block glyphs. A classic
/// console without one of those hosts gets the plain ASCII banner.
#[cfg(windows)]
fn windows_unicode_host() -> bool {
    env_set("WT_SESSION") || env_set("TERM_PROGRAM") || conemu_unicode()
}

#[cfg(windows)]
fn conemu_unicode() -> bool {
    if let Ok(value) = std::env::var("ConEmuANSI") {
        value.eq_ignore_ascii_case("ON")
    } else {
        env_set("ConEmuPID")
    }
}

#[cfg(windows)]
fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn compact(style: BannerStyle) -> String {
    let mark = if style.unicode && style.color != BannerColor::None {
        "▟█▙"
    } else {
        "><"
    };
    let version = VERSION_LABEL;
    if style.color == BannerColor::None {
        return format!("{mark} Balerx Gate  {version}");
    }
    let painted = paint(mark, style.color, BRAND);
    let ver = paint(version, style.color, BRAND);
    format!("{painted} Balerx Gate  {ver}")
}

fn plain_wide(color: BannerColor) -> String {
    let name = paint("Balerx Gate", color, BRAND);
    let tag = paint(TAGLINE, color, MUTED);
    let version = paint(VERSION_LABEL, color, BRAND);
    format!("{name}\n{tag}\n{version}")
}

fn wide_art(color: BannerColor) -> String {
    let balerx = word("BALERX");
    let gate = word("GATE");
    let mut lines = Vec::with_capacity(DRAGON.len());
    for (index, dragon) in DRAGON.iter().enumerate() {
        debug_assert_eq!(dragon.chars().count(), DRAGON_WIDTH);
        let right = match index {
            0..=4 => pad(&balerx[index], WORD_WIDTH),
            5..=9 => pad(&gate[index - 5], WORD_WIDTH),
            11 => tagline_row(),
            _ => " ".repeat(WORD_WIDTH),
        };
        lines.push(paint_wide(dragon, &right, color, index == 11));
    }
    lines.join("\n")
}

fn tagline_row() -> String {
    let version = VERSION_LABEL;
    let gap = WORD_WIDTH.saturating_sub(TAGLINE.chars().count() + version.chars().count());
    format!("{TAGLINE}{}{version}", " ".repeat(gap))
}

fn paint_wide(dragon: &str, right: &str, color: BannerColor, tagline: bool) -> String {
    let mut line = String::new();
    line.push(' ');
    line.push_str(&paint_run(dragon, color, |_| Some(BRAND)));
    line.push_str("  ");
    let span = right.chars().count().max(1);
    if tagline {
        line.push_str(&paint_tagline(right, color));
    } else {
        line.push_str(&paint_run(right, color, |index| {
            (right.chars().nth(index) != Some(' ')).then(|| gradient(index, span))
        }));
    }
    line
}

fn paint_tagline(right: &str, color: BannerColor) -> String {
    let version = VERSION_LABEL;
    let split = right
        .char_indices()
        .rev()
        .nth(version.chars().count().saturating_sub(1))
        .map_or(0, |(index, _)| index);
    let (tag, ver) = right.split_at(split);
    format!(
        "{}{}",
        paint_run(tag, color, |index| {
            (tag.chars().nth(index) != Some(' ')).then_some(MUTED)
        }),
        paint(ver, color, BRAND)
    )
}

fn paint_run(text: &str, color: BannerColor, color_at: impl Fn(usize) -> Option<Rgb>) -> String {
    if color == BannerColor::None {
        return text.to_string();
    }
    let mut out = String::new();
    let mut active: Option<Rgb> = None;
    for (index, ch) in text.chars().enumerate() {
        let next = color_at(index);
        if next != active {
            out.push_str(&switch(color, next));
            active = next;
        }
        out.push(ch);
    }
    if active.is_some() {
        out.push_str(reset());
    }
    out
}

fn paint(text: &str, color: BannerColor, rgb: Rgb) -> String {
    if color == BannerColor::None || text.is_empty() {
        return text.to_string();
    }
    format!("{}{text}{}", sequence(color, rgb), reset())
}

fn switch(color: BannerColor, next: Option<Rgb>) -> String {
    next.map_or_else(|| reset().to_string(), |rgb| sequence(color, rgb))
}

fn sequence(color: BannerColor, rgb: Rgb) -> String {
    match color {
        BannerColor::None => String::new(),
        BannerColor::Truecolor => format!("\u{1b}[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2),
        BannerColor::Ansi256 => format!("\u{1b}[38;5;{}m", xterm(rgb)),
    }
}

fn reset() -> &'static str {
    "\u{1b}[0m"
}

fn gradient(index: usize, span: usize) -> Rgb {
    let t = if span <= 1 {
        1000
    } else {
        index.saturating_mul(1000) / (span - 1)
    };
    if t < 500 {
        mix(DARK, BRAND, t.saturating_mul(2))
    } else {
        mix(BRAND, LIGHT, t.saturating_sub(500).saturating_mul(2))
    }
}

fn mix(start: Rgb, end: Rgb, t: usize) -> Rgb {
    let t = u16::try_from(t.min(1000)).unwrap_or(1000);
    (
        channel(start.0, end.0, t),
        channel(start.1, end.1, t),
        channel(start.2, end.2, t),
    )
}

fn channel(start: u8, end: u8, t: u16) -> u8 {
    let start = i32::from(start);
    let end = i32::from(end);
    let mixed = start + (end - start) * i32::from(t) / 1000;
    u8::try_from(mixed.clamp(0, 255)).unwrap_or(0)
}

fn xterm(rgb: Rgb) -> u8 {
    let cube = |component: u8| -> u8 {
        if component < 48 {
            0
        } else if component < 114 {
            1
        } else {
            u8::try_from((u16::from(component) - 35) / 40).unwrap_or(5)
        }
    };
    16 + 36 * cube(rgb.0) + 6 * cube(rgb.1) + cube(rgb.2)
}

fn word(text: &str) -> Vec<String> {
    let mut rows = vec![String::new(); 5];
    for (index, ch) in text.chars().enumerate() {
        if index > 0 {
            for row in &mut rows {
                row.push(' ');
            }
        }
        for (row, line) in rows.iter_mut().zip(glyph(ch)) {
            row.push_str(line);
        }
    }
    rows
}

fn pad(text: &str, width: usize) -> String {
    let extra = width.saturating_sub(text.chars().count());
    format!("{text}{}", " ".repeat(extra))
}

fn glyph(ch: char) -> [&'static str; 5] {
    match ch {
        'B' => ["███▄", "█  █", "███▄", "█  █", "███▀"],
        'A' => ["▄██▄", "█  █", "████", "█  █", "█  █"],
        'L' => ["█   ", "█   ", "█   ", "█   ", "███▀"],
        'E' => ["████", "█   ", "███ ", "█   ", "████"],
        'R' => ["█▀▀▄", "█  █", "█▀▀▄", "█ ▀▄", "█  █"],
        'X' => ["█  █", "▀▄▄▀", " ██ ", "▄▀▀▄", "█  █"],
        'G' => ["▄███", "█   ", "█ ▀█", "█  █", "▀██▀"],
        'T' => ["████", " ██ ", " ██ ", " ██ ", " ██ "],
        _ => ["    ", "    ", "    ", "    ", "    "],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn style(color: BannerColor, columns: usize, unicode: bool) -> BannerStyle {
        BannerStyle {
            color,
            columns,
            unicode,
        }
    }

    fn plain_text(rendered: &str) -> String {
        let mut out = String::new();
        let mut chars = rendered.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
                continue;
            }
            out.push(ch);
        }
        out
    }

    #[test]
    fn dragon_rows_share_one_width() {
        for row in DRAGON {
            assert_eq!(row.chars().count(), DRAGON_WIDTH, "{row}");
        }
    }

    #[test]
    fn glyphs_are_four_cells() {
        for ch in ['B', 'A', 'L', 'E', 'R', 'X', 'G', 'T'] {
            for line in glyph(ch) {
                assert_eq!(line.chars().count(), 4, "{ch} {line}");
            }
        }
    }

    #[test]
    fn no_color_and_narrow_widths_omit_ansi() {
        for columns in [40, 80, 100] {
            let plain = render(style(BannerColor::None, columns, true));
            assert!(!plain.contains('\u{1b}'), "{plain}");
            assert!(plain.contains("Balerx Gate"), "{plain}");
            assert!(plain.contains(VERSION_LABEL), "{plain}");
            assert!(!plain.contains('█'), "{plain}");
        }
        let narrow = render(style(BannerColor::None, 60, true));
        assert_eq!(narrow.lines().count(), 1, "{narrow}");
        let wide = render(style(BannerColor::None, 100, false));
        assert!(wide.contains(TAGLINE), "{wide}");
        assert_eq!(wide.lines().count(), 3, "{wide}");
    }

    #[test]
    fn narrow_truecolor_is_one_line_and_wide_art_uses_brand_rgb() {
        let narrow = render(style(BannerColor::Truecolor, 60, true));
        assert_eq!(narrow.lines().count(), 1, "{narrow}");
        assert!(narrow.contains("Balerx Gate"), "{narrow}");
        assert!(narrow.contains("▟█▙"), "{narrow}");
        assert!(!narrow.contains(TAGLINE), "{narrow}");
        assert!(narrow.contains("\u{1b}[38;2;176;18;46m"), "{narrow}");

        let wide = render(style(BannerColor::Truecolor, 100, true));
        let text = plain_text(&wide);
        assert!(text.lines().count() > 5, "{text}");
        assert!(text.contains(TAGLINE), "{text}");
        assert!(text.contains(VERSION_LABEL), "{text}");
        assert!(wide.contains("\u{1b}[38;2;176;18;46m"), "{wide}");
        assert!(wide.contains("\u{1b}[38;2;142;16;36m"), "{wide}");
        assert!(!wide.contains("\u{1b}[38;5;"), "{wide}");
    }

    #[test]
    fn ansi_256_uses_the_cube_and_not_truecolor() {
        let wide = render(style(BannerColor::Ansi256, 100, true));
        assert!(wide.contains("\u{1b}[38;5;"), "{wide}");
        assert!(!wide.contains("\u{1b}[38;2;"), "{wide}");
        assert!(plain_text(&wide).contains(TAGLINE), "{wide}");
    }
}
