//! Текстовые файлы, которые человек правит сам (cgmon.yaml, список Per-Site Routing):
//! принимаем UTF-8 (с BOM и без), UTF-16 (Блокнот «Юникод») и однобайтовые
//! «ANSI» Windows — cp1251 (кириллица) и cp1252 (латиница); переводы строк CRLF/CR.
//! Всё приводится к UTF-8 с LF. `normalize_file` переписывает файл в UTF-8 на
//! месте, сохранив оригинал рядом (`<файл>.orig-<кодировка>`).

/// cp1251, байты 0x80..=0xBF (0xC0..=0xFF — А..я подряд).
const CP1251_HI: [u16; 64] = [
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0xFFFD, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
    0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
];
/// cp1252, байты 0x80..=0x9F (0xA0..=0xFF — как Latin-1).
const CP1252_80: [u16; 32] = [
    0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD,
    0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178,
];

fn cp1251(b: u8) -> char {
    let u = match b {
        0..=0x7F => b as u16,
        0x80..=0xBF => CP1251_HI[(b - 0x80) as usize],
        _ => 0x0410 + (b - 0xC0) as u16,
    };
    char::from_u32(u as u32).unwrap_or('\u{FFFD}')
}

fn cp1252(b: u8) -> char {
    let u = match b {
        0x80..=0x9F => CP1252_80[(b - 0x80) as usize],
        _ => b as u16,
    };
    char::from_u32(u as u32).unwrap_or('\u{FFFD}')
}

fn utf16(b: &[u8], le: bool) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
    String::from_utf16_lossy(&units)
}

/// Байты → (текст UTF-8 с LF, имя исходной кодировки; "" — уже был чистый UTF-8 с LF).
pub fn decode(b: &[u8]) -> (String, &'static str) {
    let (text, enc) = if let Some(r) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        (String::from_utf8_lossy(r).into_owned(), "utf8-bom")
    } else if let Some(r) = b.strip_prefix(&[0xFF, 0xFE]) {
        (utf16(r, true), "utf16le")
    } else if let Some(r) = b.strip_prefix(&[0xFE, 0xFF]) {
        (utf16(r, false), "utf16be")
    } else if let Ok(s) = std::str::from_utf8(b) {
        (s.to_string(), "")
    } else {
        // однобайтовая «ANSI»: кириллица (cp1251), если старшие байты — в основном буквы
        // А..я/Ёё, иначе западная латиница (cp1252)
        // в русском тексте буквы (старшие байты) идут подряд — слово целиком; в латинице
        // акцентные буквы одиночные среди ASCII
        let letter = |x: u8| x >= 0xC0 || x == 0xA8 || x == 0xB8;
        let hi = b.iter().filter(|x| **x >= 0x80).count();
        let runs = (0..b.len()).filter(|&i| letter(b[i]) && ((i > 0 && letter(b[i - 1])) || (i + 1 < b.len() && letter(b[i + 1])))).count();
        if runs * 2 >= hi {
            (b.iter().map(|x| cp1251(*x)).collect(), "cp1251")
        } else {
            (b.iter().map(|x| cp1252(*x)).collect(), "cp1252")
        }
    };
    if text.contains('\r') {
        let t = text.replace("\r\n", "\n").replace('\r', "\n");
        return (t, if enc.is_empty() { "crlf" } else { enc });
    }
    (text, enc)
}

/// Прочитать текстовый файл в любой из понятных кодировок.
pub fn read(path: &str) -> std::io::Result<(String, &'static str)> {
    std::fs::read(path).map(|b| decode(&b))
}

/// Прочитать и, если файл был не в UTF-8/LF, переписать его в UTF-8 (оригинал —
/// рядом, один раз). Права файла сохраняются.
pub fn read_normalized(path: &str) -> std::io::Result<String> {
    let (text, enc) = read(path)?;
    if !enc.is_empty() && !crate::util::readonly() {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o600);
        let orig = format!("{path}.orig-{enc}");
        if !std::path::Path::new(&orig).exists() {
            let _ = std::fs::copy(path, &orig);
        }
        match crate::util::write_atomic(path, text.as_bytes(), mode) {
            Ok(()) => crate::log_info!("{}", tr!("{}: файл был в кодировке {} — переписан в UTF-8 (оригинал: {})", path, enc, orig)),
            Err(e) => crate::log_err!("{}: {}", path, e),
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        assert_eq!(decode("ключ: да\n".as_bytes()), ("ключ: да\n".to_string(), ""));
        assert_eq!(decode(b"\xEF\xBB\xBFa: 1\r\n"), ("a: 1\n".to_string(), "utf8-bom"));
        // «# Пароль» в cp1251
        assert_eq!(decode(b"# \xCF\xE0\xF0\xEE\xEB\xFC\r\nx: 1\r\n"), ("# Пароль\nx: 1\n".to_string(), "cp1251"));
        assert_eq!(decode(b"# \xA8\xF1\xEB\xE8 \xB9"), ("# Ёсли №".to_string(), "cp1251"));
        // латиница в cp1252: é — Latin-1, 0x80 — €
        let (t, e) = decode(b"# caf\xE9 \x80 x");
        assert_eq!(e, "cp1252");
        assert_eq!(t, "# caf\u{e9} \u{20ac} x");
        // UTF-16 LE с BOM
        let mut u = vec![0xFF, 0xFE];
        for c in "lang: ru\r\n".encode_utf16() { u.extend_from_slice(&c.to_le_bytes()); }
        assert_eq!(decode(&u), ("lang: ru\n".to_string(), "utf16le"));
    }
}
