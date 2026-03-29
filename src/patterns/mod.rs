pub mod abstracts;
use abstracts::{DUCKDB, GENERAL, POSTGRES, SANITIZER, SQLITE};
use regex::RegexSet;
use std::sync::LazyLock;

pub fn all_patterns() -> Vec<&'static str> {
    let mut patterns = Vec::new();
    patterns.extend_from_slice(GENERAL);
    patterns.extend_from_slice(SANITIZER);
    patterns.extend_from_slice(POSTGRES);
    patterns.extend_from_slice(SQLITE);
    patterns.extend_from_slice(DUCKDB);
    patterns
}

static INJECTION_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new(all_patterns()).expect("Failed to compile SQL injection patterns")
});

pub fn matched_patterns(input: &str) -> Vec<usize> {
    INJECTION_SET.matches(input).into_iter().collect()
}
