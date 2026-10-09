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

    // Every keyword lookup comes down to this loop, which is why it walks
    // the two strings together rather than index into `a`.
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

/// Slots in [`SLOTS`]: a power of two, some three times the number of words.
const SLOT_COUNT: usize = 1 << 15;

/// The most comparisons a lookup may take: what a binary search over the
/// table, upstream's way, takes every time.
const MAX_PROBES: usize = 14;

/// An empty slot.
const EMPTY: u16 = u16::MAX;

/// FNV-1a over the key as the comparison sees it: upper-cased.
const fn hash(key: &[u8]) -> usize {
    let mut hash: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < key.len() {
        hash = (hash ^ key[i].to_ascii_uppercase() as u32).wrapping_mul(0x0100_0193);
        i += 1;
    }
    // The low bits of FNV are its weakest: fold the high ones in.
    ((hash ^ (hash >> 15)) as usize) & (SLOT_COUNT - 1)
}

/// A hash table over [`SQL_KEYWORDS`]: each slot holds the index of a word,
/// or [`EMPTY`]. A word sits in the first free slot from its hash on.
static SLOTS: [u16; SLOT_COUNT] = {
    assert!(SQL_KEYWORDS.len() < EMPTY as usize);
    let mut slots = [EMPTY; SLOT_COUNT];
    let mut i = 0;
    while i < SQL_KEYWORDS.len() {
        let mut slot = hash(SQL_KEYWORDS[i].0.as_bytes());
        while slots[slot] != EMPTY {
            slot = (slot + 1) & (SLOT_COUNT - 1);
        }
        slots[slot] = i as u16;
        i += 1;
    }

    // A lookup goes through one run of taken slots at most, whatever the
    // key: no input can make it cost more than a binary search would.
    let mut run = 0;
    let mut i = 0;
    while i < 2 * SLOT_COUNT {
        run = if slots[i & (SLOT_COUNT - 1)] == EMPTY {
            0
        } else {
            run + 1
        };
        assert!(run <= MAX_PROBES);
        i += 1;
    }
    slots
};

/// Looks `key` up in the one table that holds keywords, operators and
/// fingerprints alike.
///
/// Upstream does a binary search over it (`bsearch_keyword_type`), which
/// finds the same words: those `key` equals by [`cstrcasecmp`]. Done that
/// way, the lookups were half of what detecting SQLi cost.
pub(crate) fn lookup_word(key: &[u8]) -> Option<TokenType> {
    let mut slot = hash(key);
    loop {
        let index = SLOTS[slot];
        if index == EMPTY {
            return None;
        }
        let (word, ty) = SQL_KEYWORDS[usize::from(index)];
        if cstrcasecmp(word.as_bytes(), key) == Ordering::Equal {
            return Some(ty);
        }
        slot = (slot + 1) & (SLOT_COUNT - 1);
    }
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

    /// Upstream's `bsearch_keyword_type`, to check [`lookup_word`] against.
    fn upstream_lookup(key: &[u8]) -> Option<TokenType> {
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

    #[test]
    fn finds_what_upstream_finds() {
        let check = |key: &[u8]| {
            assert_eq!(
                lookup_word(key),
                upstream_lookup(key),
                "{}",
                key.escape_ascii()
            );
        };

        // Nothing, and every one and two bytes there are: the operators.
        check(b"");
        for a in 0..=u8::MAX {
            check(&[a]);
            for b in 0..=u8::MAX {
                check(&[a, b]);
            }
        }

        // Every word of the table, whole and cut short, in lower case and
        // with something appended.
        let tails: [&[u8]; 6] = [b"", b"\0", b"A", b"z", b" ", b"\xff"];
        for &(word, _) in &SQL_KEYWORDS {
            let word = word.as_bytes();
            for cut in [word.len() - 1, word.len()] {
                for tail in tails {
                    check(&[&word[..cut].to_ascii_lowercase(), tail].concat());
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
