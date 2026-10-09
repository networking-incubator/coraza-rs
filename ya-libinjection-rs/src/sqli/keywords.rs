use core::cmp::Ordering;

use super::keyword_table::SQL_KEYWORDS;
use super::token::TokenType;

/// Upstream's `cstrcasecmp`: compares the upper-case C string `a` with the
/// arbitrary bytes `b`, upper-casing `b` on the fly.
///
/// `a` stands in for a NUL-terminated string. Reaching its terminator while
/// `b` holds a NUL at the same offset is "less", not "equal".
pub(crate) fn cstrcasecmp(a: &[u8], b: &[u8]) -> Ordering {
    for (i, cb) in b.iter().map(u8::to_ascii_uppercase).enumerate() {
        let ca = a.get(i).copied().unwrap_or(0);
        if ca != cb {
            // Upstream subtracts `char`s, signed on its reference platform.
            // Only keys that cannot be in the ASCII table are affected.
            return ca.cast_signed().cmp(&cb.cast_signed());
        }
        if ca == 0 {
            return Ordering::Less;
        }
    }
    if a.len() == b.len() {
        Ordering::Equal
    } else {
        Ordering::Greater
    }
}

/// Upstream's `bsearch_keyword_type` over the one table that holds keywords,
/// operators and fingerprints alike.
pub(crate) fn lookup_word(key: &[u8]) -> Option<TokenType> {
    let mut left = 0;
    let mut right = SQL_KEYWORDS.len() - 1;
    while left < right {
        let pos = left.midpoint(right);
        if cstrcasecmp(SQL_KEYWORDS[pos].0.as_bytes(), key) == Ordering::Less {
            left = pos + 1;
        } else {
            right = pos;
        }
    }
    let (word, ty) = SQL_KEYWORDS[left];
    (cstrcasecmp(word.as_bytes(), key) == Ordering::Equal).then_some(ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_entry_is_found() {
        for &(word, ty) in &SQL_KEYWORDS {
            assert_eq!(lookup_word(word.as_bytes()), Some(ty), "{word}");
            assert_eq!(
                lookup_word(word.to_ascii_lowercase().as_bytes()),
                Some(ty),
                "{word}"
            );
        }
    }

    #[test]
    fn table_matches_upstream() {
        let source = crate::corpus::upstream_source("src/libinjection_sqli_data.h");
        let body = crate::corpus::c_array_body(&source, "sql_keywords[] = {");
        // Each entry reads `{"WORD", 't'},`.
        let upstream: Vec<(&str, u8)> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("{\"")?.strip_suffix("'},"))
            .map(|entry| {
                let (word, ty) = entry.rsplit_once("\", '").unwrap();
                (word, ty.as_bytes()[0])
            })
            .collect();

        let table: Vec<(&str, u8)> = SQL_KEYWORDS
            .iter()
            .map(|&(word, ty)| (word, ty.as_byte()))
            .collect();
        assert!(table == upstream, "keyword table is out of date");
    }

    #[test]
    fn misses() {
        assert_eq!(lookup_word(b""), None);
        assert_eq!(lookup_word(b"SELEC"), None);
        assert_eq!(lookup_word(b"SELECTS"), None);
        assert_eq!(lookup_word(b"SELECT\0"), None);
        assert_eq!(lookup_word(b"\xff\xfe"), None);
    }

    #[test]
    fn embedded_nul_is_not_equal() {
        assert_eq!(cstrcasecmp(b"NOT", b"NOT\0"), Ordering::Less);
        assert_eq!(cstrcasecmp(b"NOT", b"not"), Ordering::Equal);
        assert_eq!(cstrcasecmp(b"NOT", b"no"), Ordering::Greater);
    }
}
