//! Search matching for `reg query /f`.
//!
//! `reg query` can filter a key tree by a pattern (`/f`), restricted to key
//! names (`/k`), value data (`/d`), or, by default, key names, value names, and
//! data. Matching is case-insensitive substring by default, with case-sensitive
//! (`/c`) and exact-match (`/e`) modifiers. This module is the pure matcher; the
//! CLI walks the tree and applies it.

/// A compiled search filter.
#[derive(Debug, Clone)]
pub struct Filter {
    pattern: String,
    case_sensitive: bool,
    exact: bool,
    /// Whether key names are in scope.
    pub in_keys: bool,
    /// Whether value names are in scope.
    pub in_value_names: bool,
    /// Whether value data is in scope.
    pub in_data: bool,
}

impl Filter {
    /// Build a filter. `k` is the `/k` flag (key names only), `d` is `/d` (data
    /// only); with neither, all three scopes are searched. `case_sensitive` is
    /// `/c`, `exact` is `/e`.
    pub fn new(pattern: impl Into<String>, k: bool, d: bool, case_sensitive: bool, exact: bool) -> Filter {
        let (in_keys, in_value_names, in_data) = match (k, d) {
            (false, false) => (true, true, true),
            (true, false) => (true, false, false),
            (false, true) => (false, false, true),
            (true, true) => (true, false, true),
        };
        Filter {
            pattern: pattern.into(),
            case_sensitive,
            exact,
            in_keys,
            in_value_names,
            in_data,
        }
    }

    /// Does `text` match the pattern under the case and exact-match rules?
    pub fn text_matches(&self, text: &str) -> bool {
        if self.case_sensitive {
            if self.exact {
                text == self.pattern
            } else {
                text.contains(&self.pattern)
            }
        } else {
            let h = text.to_uppercase();
            let n = self.pattern.to_uppercase();
            if self.exact {
                h == n
            } else {
                h.contains(&n)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_case_insensitive_by_default() {
        let f = Filter::new("foo", false, false, false, false);
        assert!(f.text_matches("a FOObar"));
        assert!(f.text_matches("foo"));
        assert!(!f.text_matches("baz"));
        assert!(f.in_keys && f.in_value_names && f.in_data);
    }

    #[test]
    fn case_sensitive_and_exact() {
        let cs = Filter::new("Foo", false, false, true, false);
        assert!(cs.text_matches("xFooy"));
        assert!(!cs.text_matches("xfooy"));

        let exact = Filter::new("Foo", false, false, false, true);
        assert!(exact.text_matches("FOO"));
        assert!(!exact.text_matches("Foobar"));
    }

    #[test]
    fn scope_flags() {
        let keys = Filter::new("x", true, false, false, false);
        assert!(keys.in_keys && !keys.in_value_names && !keys.in_data);
        let data = Filter::new("x", false, true, false, false);
        assert!(!data.in_keys && !data.in_value_names && data.in_data);
        let both = Filter::new("x", true, true, false, false);
        assert!(both.in_keys && !both.in_value_names && both.in_data);
    }
}
