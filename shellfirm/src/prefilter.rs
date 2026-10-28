//! Case folding for the built-in check prefilter.
//!
//! `build.rs` derives, for every built-in check, a set of literals of which
//! at least one must occur in any text the check's regex matches (see
//! `required_literals` there). Literals are stored folded with
//! [`fold_char`], and the text is folded the same way before the search, so
//! a case-insensitive `(?i)drop` still yields the literal `drop`.
//!
//! The prefilter only has to be *necessary*, never sufficient: a check whose
//! literals are all absent from the folded text cannot match, so its regex
//! is never compiled for that command. This file is shared with `build.rs`
//! (`#[path]` include), which keeps both sides folding identically.

/// Fold one character: ASCII and simple Unicode lowercase, plus the two
/// characters whose case folding is not their lowercase form (`ſ` → `s`,
/// Kelvin sign → `k`). Any deterministic mapping is correct here, as long as
/// build.rs and the runtime use the same one.
#[must_use]
pub fn fold_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_lowercase();
    }
    match c {
        '\u{17F}' => 's',
        '\u{212A}' => 'k',
        _ => {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) => l,
                _ => c,
            }
        }
    }
}

/// Fold a whole text with [`fold_char`].
#[must_use]
pub fn fold(text: &str) -> String {
    if text.is_ascii() {
        text.to_ascii_lowercase()
    } else {
        text.chars().map(fold_char).collect()
    }
}
