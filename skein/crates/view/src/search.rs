/// Most terms taken from one query; the rest are ignored.
pub const MAX_TERMS: usize = 16;

/// Turns user text into an FTS5 query that cannot be a syntax error: every whitespace-separated
/// term becomes a quoted string (inner `"` doubled), all terms must match, and a trailing `*`
/// on a term asks for a prefix match. FTS operators typed by the user (`OR`, `NEAR`, `-`, `:`,
/// parentheses) are searched for as words. `None` when nothing searchable is left.
pub fn fts_query(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split_whitespace()
        .filter_map(|raw| {
            let (word, prefix) = match raw.strip_suffix('*') {
                Some(w) => (w.trim_end_matches('*'), true),
                None => (raw, false),
            };
            if !word.chars().any(char::is_alphanumeric) {
                return None;
            }
            let quoted = format!("\"{}\"", word.replace('"', "\"\""));
            Some(if prefix { format!("{quoted}*") } else { quoted })
        })
        .take(MAX_TERMS)
        .collect();
    (!terms.is_empty()).then(|| terms.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_every_term() {
        assert_eq!(fts_query("garden report").unwrap(), "\"garden\" \"report\"");
        assert_eq!(
            fts_query("  pat@example.com ").unwrap(),
            "\"pat@example.com\""
        );
        assert_eq!(fts_query("gard*").unwrap(), "\"gard\"*");
    }

    #[test]
    fn neutralizes_fts_syntax() {
        assert_eq!(fts_query("a\"b").unwrap(), "\"a\"\"b\"");
        assert_eq!(fts_query("x OR y").unwrap(), "\"x\" \"OR\" \"y\"");
        assert_eq!(fts_query("subject:secret").unwrap(), "\"subject:secret\"");
        assert_eq!(fts_query("NEAR(a b)").unwrap(), "\"NEAR(a\" \"b)\"");
        assert_eq!(fts_query("\" * ( ) -"), None);
        assert_eq!(fts_query(""), None);
        assert_eq!(
            fts_query(&"w ".repeat(40)).unwrap().matches('"').count(),
            MAX_TERMS * 2
        );
    }
}
