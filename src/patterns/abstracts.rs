use crate::patterns::definitions::{DUCKDB, Database, GENERAL, POSTGRES, PatternEntry, SQLITE};
use regex::RegexSet;

use std::sync::LazyLock;

#[derive(Debug)]
pub struct DatabaseMatches {
    pub database: Database,
    pub patterns: Vec<&'static PatternEntry>,
}

#[derive(Debug)]
pub struct InjectionAnalysis {
    pub is_malicious: bool,
    pub matches: Vec<DatabaseMatches>,
}

pub struct CompiledPatterns {
    set: RegexSet,
    pattern_map: Vec<(Database, &'static PatternEntry)>,
}

impl CompiledPatterns {
    pub fn matches(&self, input: &str) -> Vec<usize> {
        self.set.matches(input).into_iter().collect()
    }

    pub fn get_pattern(&self, idx: usize) -> Option<&(Database, &'static PatternEntry)> {
        self.pattern_map.get(idx)
    }
}

static DB_PATTERNS: &[(Database, &[PatternEntry])] = &[
    (Database::General, GENERAL),
    (Database::Postgres, POSTGRES),
    (Database::Sqlite, SQLITE),
    (Database::DuckDb, DUCKDB),
];

pub static ALL_PATTERNS: LazyLock<CompiledPatterns> = LazyLock::new(|| {
    let mut regex_patterns = Vec::new();
    let mut pattern_map = Vec::new();

    for (db, patterns) in DB_PATTERNS {
        for entry in patterns.iter() {
            regex_patterns.push(entry.pattern);
            pattern_map.push((db.clone(), entry));
        }
    }

    CompiledPatterns {
        set: RegexSet::new(&regex_patterns).expect("Failed to compile SQL injection patterns"),
        pattern_map,
    }
});
