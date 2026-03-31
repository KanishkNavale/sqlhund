use crate::patterns::abstracts::{ALL_PATTERNS, InjectionAnalysis};
use std::collections::HashSet;

fn get_matches(input: &str) -> Vec<usize> {
    ALL_PATTERNS.matches(input)
}

pub fn matched_patterns(input: &str) -> Vec<usize> {
    get_matches(input)
}

pub fn audit_patterns(input: &str) -> InjectionAnalysis {
    let matches: Vec<usize> = get_matches(input);

    if matches.is_empty() {
        return InjectionAnalysis {
            is_malicious: false,
            affected_databases: vec![],
        };
    }

    let mut seen = HashSet::new();
    let index_map = ALL_PATTERNS.index_map();

    let affected_databases = matches
        .iter()
        .filter_map(|&idx| {
            let db = index_map[idx].clone();
            seen.insert(db.clone()).then_some(db)
        })
        .collect();

    InjectionAnalysis {
        is_malicious: true,
        affected_databases,
    }
}
