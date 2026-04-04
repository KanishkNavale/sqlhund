use crate::patterns::abstracts::{ALL_PATTERNS, DatabaseMatches, InjectionAnalysis};
use crate::patterns::definitions::{Database, PatternEntry};
use std::collections::HashMap;

pub fn get_pattern_matches(input: &str) -> Vec<usize> {
    ALL_PATTERNS.matches(input)
}

pub fn audit_patterns(input: &str) -> InjectionAnalysis {
    let match_indices: Vec<usize> = get_pattern_matches(input);

    if match_indices.is_empty() {
        return InjectionAnalysis {
            is_malicious: false,
            matches: vec![],
        };
    }

    // Group matched patterns by database
    let mut db_patterns: HashMap<Database, Vec<&'static PatternEntry>> = HashMap::new();

    for idx in match_indices {
        if let Some((db, pattern)) = ALL_PATTERNS.get_pattern(idx) {
            db_patterns.entry(db.clone()).or_default().push(pattern);
        }
    }

    // Convert to Vec<DatabaseMatches>
    let mut matches: Vec<DatabaseMatches> = db_patterns
        .into_iter()
        .map(|(database, patterns)| DatabaseMatches { database, patterns })
        .collect();

    // Sort by database name for consistent output
    matches.sort_by(|a, b| a.database.as_str().cmp(b.database.as_str()));

    InjectionAnalysis {
        is_malicious: true,
        matches,
    }
}
