use core::cmp::Ordering;

use super::keyword_table::SQL_KEYWORDS;
use super::token::TokenType;

/// Upstream's `cstrcasecmp`: compares the upper-case C string `a` with the
/// arbitrary bytes `b`, upper-casing `b` on the fly.
///
/// `a` stands in for a NUL-terminated string, and must hold no NUL of its
/// own. Its terminator meeting a NUL in `b` is "less", not "equal".
pub(crate) fn cstrcasecmp(a: &[u8], b: &[u8]) -> Ordering {
    // Upstream subtracts `char`s, signed on its reference platform. Only
    // keys that cannot be in the ASCII table are affected.
    let compare = |ca: u8, cb: u8| ca.cast_signed().cmp(&cb.cast_signed());

    // The keyword lookup spends most of its time in this loop, which is why
    // it walks the two strings together rather than index into `a`.
    for (&ca, cb) in a.iter().zip(b.iter().map(u8::to_ascii_uppercase)) {
        if ca != cb {
            return compare(ca, cb);
        }
    }
    match b.get(a.len()).map(u8::to_ascii_uppercase) {
        // `b` goes on past the end of `a`: its next byte meets the NUL.
        Some(0) => Ordering::Less,
        Some(cb) => compare(0, cb),
        None if a.len() == b.len() => Ordering::Equal,
        // `a` goes on past the end of `b`.
        None => Ordering::Greater,
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

    /// `cstrcasecmp` as upstream writes it, one byte at a time.
    fn upstream_cstrcasecmp(a: &[u8], b: &[u8]) -> Ordering {
        for (i, cb) in b.iter().map(u8::to_ascii_uppercase).enumerate() {
            let ca = a.get(i).copied().unwrap_or(0);
            if ca != cb {
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

    #[test]
    fn compares_as_upstream_does() {
        let tails: [&[u8]; 6] = [b"", b"\0", b"A", b"z", b"\x7f", b"\xff"];
        for (i, &(word, _)) in SQL_KEYWORDS.iter().enumerate() {
            let word = word.as_bytes();
            assert!(!word.contains(&0), "a NUL in the table");

            // Every prefix of the word, in lower case, with something
            // appended, against the word and its neighbour in the table.
            let neighbour = SQL_KEYWORDS[(i + 1) % SQL_KEYWORDS.len()].0.as_bytes();
            for cut in 0..=word.len() {
                for tail in tails {
                    let key = [&word[..cut].to_ascii_lowercase(), tail].concat();
                    for a in [word, neighbour] {
                        assert_eq!(
                            cstrcasecmp(a, &key),
                            upstream_cstrcasecmp(a, &key),
                            "{} against {}",
                            a.escape_ascii(),
                            key.escape_ascii()
                        );
                    }
                }
            }
        }
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
