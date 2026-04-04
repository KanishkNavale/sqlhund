use sqlhund::{analyze_query, is_query_malicious};

static SHOULD_BLOCK: &[&str] = &[
    "DELETE FROM users",
    "INSERT INTO users (id) VALUES (1)",
    "UPDATE users SET name = 'x' WHERE id = 1",
    "SELECT * FROM (SELECT id FROM users)",
    "SELECT a FROM t UNION SELECT b FROM t2",
    "SELECT * FROM users; DROP TABLE users",
    "SELECT * FROM users WHERE id = 1 OR 1=1",
];

static SHOULD_PASS: &[&str] = &[
    "SELECT * FROM users WHERE id = 1",
    "SELECT id, name FROM users WHERE status = 'active'",
    "SELECT COUNT(*) FROM orders WHERE created_at > '2024-01-01'",
];

#[test]
fn test_blocking_input() {
    for query in SHOULD_BLOCK {
        assert!(is_query_malicious(query), "Should be blocked: {}", query);
    }
}

#[test]
fn test_non_blocking_input() {
    for query in SHOULD_PASS {
        assert!(!is_query_malicious(query), "Should pass: {}", query);
    }
}

#[test]
fn test_analyze_query() {
    for query in SHOULD_BLOCK {
        let analysis = analyze_query(query);
        assert!(analysis.is_malicious, "Should be malicious: {}", query);
        assert!(
            !analysis.matches.is_empty(),
            "Should affect databases: {}",
            query
        );
    }
}

#[test]
fn test_analyze_query_non_malicious() {
    for query in SHOULD_PASS {
        let analysis = analyze_query(query);
        assert!(!analysis.is_malicious, "Should not be malicious: {}", query);
        assert!(
            analysis.matches.is_empty(),
            "Should not affect databases: {}",
            query
        );
    }
}
