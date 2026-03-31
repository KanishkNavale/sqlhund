use crate::patterns::definitions::{DUCKDB, GENERAL, POSTGRES, SQLITE};
use regex::RegexSet;

use std::sync::LazyLock;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Database {
    General,
    Sqlite,
    Postgres,
    DuckDb,
}

impl Database {
    pub fn as_str(&self) -> &'static str {
        match self {
            Database::General => "general",
            Database::Sqlite => "sqlite",
            Database::Postgres => "postgres",
            Database::DuckDb => "duckdb",
        }
    }
}

#[derive(Debug)]
pub struct InjectionAnalysis {
    pub is_malicious: bool,
    pub affected_databases: Vec<Database>,
}

pub struct CompiledPatterns {
    set: RegexSet,
    index_map: Vec<Database>,
}

impl CompiledPatterns {
    pub fn matches(&self, input: &str) -> Vec<usize> {
        self.set.matches(input).into_iter().collect()
    }

    pub fn index_map(&self) -> &Vec<Database> {
        &self.index_map
    }
}

static DB_PATTERNS: &[(Database, &[&str])] = &[
    (Database::General, GENERAL),
    (Database::Postgres, POSTGRES),
    (Database::Sqlite, SQLITE),
    (Database::DuckDb, DUCKDB),
];

pub static ALL_PATTERNS: LazyLock<CompiledPatterns> = LazyLock::new(|| {
    let mut all_patterns = Vec::new();
    let mut index_map = Vec::new();

    for (db, patterns) in DB_PATTERNS {
        for &pattern in *patterns {
            all_patterns.push(pattern);
            index_map.push(db.clone());
        }
    }

    CompiledPatterns {
        set: RegexSet::new(&all_patterns).expect("Failed to compile SQL injection patterns"),
        index_map,
    }
});
