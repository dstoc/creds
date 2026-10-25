use std::{fmt, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD};
use qrcode::{Color, QrCode, types::QrResult};

const QUIET_ZONE: usize = 4;
const KITTY_CHUNK_BYTES: usize = 4096;
const KITTY_MAX_COLUMNS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    Braille,
    Sextant,
    #[default]
    Half,
    Kitty,
}

impl Mode {
    pub const ALL: [Self; 4] = [Self::Braille, Self::Sextant, Self::Half, Self::Kitty];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Braille => "braille",
            Self::Sextant => "sextant",
            Self::Half => "half",
            Self::Kitty => "kitty",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseModeError(String);

impl fmt::Display for ParseModeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid qr_mode {:?}; expected one of: braille, sextant, half, kitty",
            self.0
        )
    }
}

impl std::error::Error for ParseModeError {}

impl FromStr for Mode {
    type Err = ParseModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "braille" => Ok(Self::Braille),
            "sextant" => Ok(Self::Sextant),
            "half" => Ok(Self::Half),
            "kitty" => Ok(Self::Kitty),
            _ => Err(ParseModeError(value.to_owned())),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    size: usize,
    dark_modules: Vec<bool>,
}

impl Matrix {
    fn from_qr_code(code: QrCode) -> Self {
        let size = code.width();
        let dark_modules = code
            .into_colors()
            .into_iter()
            .map(|color| color == Color::Dark)
            .collect();
        Self { size, dark_modules }
    }

    #[cfg(test)]
    fn from_rows(rows: &[&[bool]]) -> Self {
        let size = rows.len();
        let dark_modules = rows.iter().flat_map(|row| row.iter().copied()).collect();
        assert!(rows.iter().all(|row| row.len() == size));
        Self { size, dark_modules }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    fn is_dark(&self, x: usize, y: usize) -> bool {
        if x < QUIET_ZONE
            || y < QUIET_ZONE
            || x >= self.size + QUIET_ZONE
            || y >= self.size + QUIET_ZONE
        {
            return false;
        }
        let module_x = x - QUIET_ZONE;
        let module_y = y - QUIET_ZONE;
        self.dark_modules[module_y * self.size + module_x]
    }

    fn rendered_dimensions(&self) -> (usize, usize) {
        (self.size + QUIET_ZONE * 2, self.size + QUIET_ZONE * 2)
    }
}

pub enum Rendered {
    Text(String),
    KittyProtocol(String),
}

pub fn encode(data: &str) -> QrResult<Matrix> {
    QrCode::new(data.as_bytes()).map(Matrix::from_qr_code)
}

pub fn render(matrix: &Matrix, mode: Mode) -> Rendered {
    match mode {
        Mode::Braille => Rendered::Text(render_braille(matrix)),
        Mode::Sextant => Rendered::Text(render_sextant(matrix)),
        Mode::Half => Rendered::Text(render_half(matrix)),
        Mode::Kitty => Rendered::KittyProtocol(render_kitty(matrix)),
    }
}

fn render_with_packing(
    matrix: &Matrix,
    modules_wide: usize,
    modules_high: usize,
    mut encode_cell: impl FnMut(u8) -> char,
) -> String {
    let (width, height) = matrix.rendered_dimensions();
    let columns = width.div_ceil(modules_wide);
    let rows = height.div_ceil(modules_high);
    let mut output = String::new();
    output.push_str("\x1b[30;47m");
    for cell_y in 0..rows {
        for cell_x in 0..columns {
            let mut mask = 0_u8;
            for module_y in 0..modules_high {
                for module_x in 0..modules_wide {
                    let x = cell_x * modules_wide + module_x;
                    let y = cell_y * modules_high + module_y;
                    if matrix.is_dark(x, y) {
                        let bit = module_y * modules_wide + module_x;
                        mask |= 1 << bit;
                    }
                }
            }
            output.push(encode_cell(mask));
        }
        if cell_y + 1 < rows {
            output.push('\n');
        }
    }
    output.push_str("\x1b[0m");
    output
}

fn render_braille(matrix: &Matrix) -> String {
    render_with_packing(matrix, 2, 4, |mask| {
        let dots = [0, 3, 1, 4, 2, 5, 6, 7];
        let mut braille = 0_u8;
        for (module, dot) in dots.into_iter().enumerate() {
            if mask & (1 << module) != 0 {
                braille |= 1 << dot;
            }
        }
        char::from_u32(0x2800 + u32::from(braille)).unwrap()
    })
}

fn sextant_codepoint(mask: u8) -> u32 {
    match mask {
        0 => 0x20,
        21 => 0x258c, // Existing left half block.
        42 => 0x2590, // Existing right half block.
        63 => 0x2588, // Existing full block.
        _ => {
            let skipped = u32::from(mask > 21) + u32::from(mask > 42);
            0x1fb00 + u32::from(mask) - 1 - skipped
        }
    }
}

fn render_sextant(matrix: &Matrix) -> String {
    render_with_packing(matrix, 2, 3, |mask| {
        char::from_u32(sextant_codepoint(mask)).unwrap()
    })
}

fn render_half(matrix: &Matrix) -> String {
    render_with_packing(matrix, 1, 2, |mask| match mask {
        0 => ' ',
        1 => '▀',
        2 => '▄',
        3 => '█',
        _ => unreachable!("half-block mask has only two modules"),
    })
}

fn render_kitty(matrix: &Matrix) -> String {
    let (width, height) = matrix.rendered_dimensions();
    let mut rgb = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            let color = if matrix.is_dark(x, y) { 0 } else { 255 };
            rgb.extend_from_slice(&[color, color, color]);
        }
    }
    let encoded = STANDARD.encode(rgb);
    let columns = width.min(KITTY_MAX_COLUMNS);
    // Terminal cells are approximately twice as high as they are wide. This
    // keeps the square QR image square when the terminal scales it to cells.
    let rows = columns.div_ceil(2);
    let chunks = encoded.as_bytes().chunks(KITTY_CHUNK_BYTES);
    let chunk_count = chunks.len();
    let mut output = String::with_capacity(encoded.len() + chunk_count * 32);
    for (index, chunk) in chunks.enumerate() {
        let more = u8::from(index + 1 < chunk_count);
        if index == 0 {
            output.push_str(&format!(
                "\x1b_Ga=T,f=24,s={width},v={height},c={columns},r={rows},q=2,m={more};"
            ));
        } else {
            output.push_str(&format!("\x1b_Gm={more};"));
        }
        output.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        output.push_str("\x1b\\");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestColor {
        Black,
        White,
    }

    fn effective_colors(
        text: &str,
        default_fg: TestColor,
        default_bg: TestColor,
    ) -> (TestColor, TestColor) {
        let mut foreground = default_fg;
        let mut background = default_bg;
        let mut first_character_colors = None;
        let mut chars = text.chars();
        while let Some(character) = chars.next() {
            if character == '\x1b' {
                assert_eq!(chars.next(), Some('['));
                let mut parameters = String::new();
                loop {
                    let parameter = chars.next().expect("complete SGR sequence");
                    if parameter == 'm' {
                        break;
                    }
                    parameters.push(parameter);
                }
                for parameter in parameters.split(';') {
                    match parameter {
                        "0" => {
                            foreground = default_fg;
                            background = default_bg;
                        }
                        "30" => foreground = TestColor::Black,
                        "47" => background = TestColor::White,
                        _ => panic!("unexpected SGR parameter {parameter:?}"),
                    }
                }
            } else if first_character_colors.is_none() {
                first_character_colors = Some((foreground, background));
            }
        }
        assert_eq!(
            first_character_colors,
            Some((TestColor::Black, TestColor::White))
        );
        (foreground, background)
    }

    fn known_matrix() -> Matrix {
        Matrix::from_rows(&[
            &[true, false, true],
            &[false, true, false],
            &[true, true, false],
        ])
    }

    fn lines(rendered: Rendered) -> Vec<String> {
        let Rendered::Text(text) = rendered else {
            panic!("expected text output");
        };
        let body = text
            .strip_prefix("\x1b[30;47m")
            .unwrap()
            .strip_suffix("\x1b[0m")
            .unwrap();
        body.split('\n').map(str::to_owned).collect()
    }

    #[test]
    fn text_renderers_use_black_on_white_and_reset_terminal_attributes() {
        for mode in [Mode::Braille, Mode::Sextant, Mode::Half] {
            let Rendered::Text(text) = render(&known_matrix(), mode) else {
                panic!("expected text output for {mode}");
            };

            for (default_fg, default_bg) in [
                (TestColor::White, TestColor::Black),
                (TestColor::Black, TestColor::White),
            ] {
                assert_eq!(
                    effective_colors(&text, default_fg, default_bg),
                    (default_fg, default_bg),
                    "{mode} should restore the terminal colors"
                );
            }
        }
    }

    #[test]
    fn parses_the_four_configured_modes_and_defaults_to_half() {
        assert_eq!(Mode::default(), Mode::Half);
        for (name, expected) in [
            ("braille", Mode::Braille),
            ("sextant", Mode::Sextant),
            ("half", Mode::Half),
            ("kitty", Mode::Kitty),
        ] {
            assert_eq!(name.parse::<Mode>().unwrap(), expected);
            assert_eq!(expected.to_string(), name);
        }
        assert!(
            "pixels"
                .parse::<Mode>()
                .unwrap_err()
                .to_string()
                .contains("braille, sextant, half, kitty")
        );
    }

    #[test]
    fn braille_packs_two_by_four_with_quiet_zone_and_partial_padding() {
        let rendered = lines(render(&known_matrix(), Mode::Braille));
        assert_eq!(rendered.len(), 3); // ceil((3 + 8) / 4)
        assert!(rendered.iter().all(|line| line.chars().count() == 6)); // ceil((3 + 8) / 2)
        assert_eq!(rendered[1].chars().nth(2), Some('⠵'));
        assert_eq!(rendered[1].chars().nth(3), Some('⠁'));
    }

    #[test]
    fn sextant_packs_two_by_three_and_uses_existing_half_and_full_blocks() {
        let rendered = lines(render(&known_matrix(), Mode::Sextant));
        assert_eq!(rendered.len(), 4); // ceil((3 + 8) / 3)
        assert!(rendered.iter().all(|line| line.chars().count() == 6));
        assert_eq!(rendered[1].chars().nth(2), Some('🬢'));
        assert_eq!(rendered[1].chars().nth(3), Some('🬃'));
        assert_eq!(sextant_codepoint(21), 0x258c);
        assert_eq!(sextant_codepoint(42), 0x2590);
        assert_eq!(sextant_codepoint(63), 0x2588);
    }

    #[test]
    fn half_packs_one_by_two_with_explicit_dark_and_light_module_orientation() {
        let rendered = lines(render(&known_matrix(), Mode::Half));
        assert_eq!(rendered.len(), 6); // ceil((3 + 8) / 2)
        assert!(rendered.iter().all(|line| line.chars().count() == 11));
        assert_eq!(rendered[2].chars().nth(4), Some('▀'));
        assert_eq!(rendered[2].chars().nth(5), Some('▄'));
        assert_eq!(rendered[3].chars().nth(4), Some('▀'));
    }

    #[test]
    fn kitty_output_is_chunked_rgb_protocol_with_a_white_quiet_zone() {
        let Rendered::KittyProtocol(protocol) = render(&known_matrix(), Mode::Kitty) else {
            panic!("expected Kitty output");
        };
        let (control, rest) = protocol.split_once(';').unwrap();
        assert!(control.starts_with("\x1b_Ga=T,f=24,s=11,v=11,c=11,r=6,q=2,m=0"));
        let (encoded, terminator) = rest.split_once("\x1b\\").unwrap();
        assert!(terminator.is_empty());
        let rgb = STANDARD.decode(encoded).unwrap();
        assert_eq!(rgb.len(), 11 * 11 * 3);
        assert_eq!(&rgb[..3], &[255, 255, 255]);
        let first_qr_module = (4 * 11 + 4) * 3;
        assert_eq!(&rgb[first_qr_module..first_qr_module + 3], &[0, 0, 0]);
    }

    #[test]
    fn kitty_protocol_splits_large_images_into_complete_base64_chunks() {
        let rows = vec![vec![true; 40]; 40];
        let row_refs = rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let matrix = Matrix::from_rows(&row_refs);
        let Rendered::KittyProtocol(protocol) = render(&matrix, Mode::Kitty) else {
            panic!("expected Kitty output");
        };
        let chunks = protocol
            .split("\x1b\\")
            .filter(|chunk| !chunk.is_empty())
            .collect::<Vec<_>>();
        assert!(chunks.len() > 1);
        assert!(chunks[0].starts_with("\x1b_Ga=T,f=24,s=48,v=48,c=48,r=24,q=2,m=1;"));
        assert!(chunks[0].len() - chunks[0].find(';').unwrap() - 1 == KITTY_CHUNK_BYTES);
        for chunk in &chunks[1..chunks.len() - 1] {
            assert!(chunk.starts_with("\x1b_Gm=1;"));
            assert_eq!(chunk.len() - "\x1b_Gm=1;".len(), KITTY_CHUNK_BYTES);
        }
        assert!(chunks.last().unwrap().starts_with("\x1b_Gm=0;"));
    }

    #[test]
    fn url_encoding_produces_a_square_qr_matrix() {
        let matrix = encode("https://example.test/approval#request=synthetic").unwrap();
        assert!(matrix.size() >= 21);
        assert!(matrix.dark_modules.len() == matrix.size() * matrix.size());
        assert!(matrix.is_dark(4, 4));
        assert!(!matrix.is_dark(0, 0));
    }
}
