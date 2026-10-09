//! Byte-string helpers standing in for the C library calls upstream leans on.

/// `memchr` over `s[from..]`, returning an index into `s`.
pub(crate) fn find_byte(s: &[u8], from: usize, byte: u8) -> Option<usize> {
    s[from..].iter().position(|&b| b == byte).map(|i| from + i)
}

/// Upstream's `memchr2`: the first occurrence of the pair `c0 c1`.
pub(crate) fn find_pair(haystack: &[u8], c0: u8, c1: u8) -> Option<usize> {
    haystack.windows(2).position(|w| w[0] == c0 && w[1] == c1)
}

/// Upstream's `my_memmem`.
pub(crate) fn find_slice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A membership table for `strchr(accept, ch) != NULL`.
///
/// `strchr` also matches the NUL that terminates `accept`, so NUL is a member
/// of every set, whether or not upstream spelled it out.
pub(crate) const fn byte_set(accept: &[u8]) -> [bool; 256] {
    let mut set = [false; 256];
    set[0] = true;
    let mut i = 0;
    while i < accept.len() {
        set[accept[i] as usize] = true;
        i += 1;
    }
    set
}

/// Upstream's `strlenspn`: length of the leading run of bytes in `accept`.
pub(crate) fn span(s: &[u8], accept: &[bool; 256]) -> usize {
    s.iter()
        .position(|&b| !accept[usize::from(b)])
        .unwrap_or(s.len())
}

/// Upstream's `strlencspn`: length of the leading run of bytes not in `reject`.
pub(crate) fn cspan(s: &[u8], reject: &[bool; 256]) -> usize {
    s.iter()
        .position(|&b| reject[usize::from(b)])
        .unwrap_or(s.len())
}
