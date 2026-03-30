use injectdb::is_query_malicious;

#[test]
fn test_blocking_input() {
    let should_block = vec![
        "DELETE FROM users",
        "INSERT INTO users (id) VALUES (1)",
        "UPDATE users SET name = 'x' WHERE id = 1",
        "SELECT * FROM (SELECT id FROM users)",
        "SELECT a FROM t UNION SELECT b FROM t2",
        "SELECT * FROM users; DROP TABLE users",
        "SELECT * FROM users WHERE id = 1 OR 1=1",
    ];

    for query in &should_block {
        assert!(is_query_malicious(query), "Should be blocked: {}", query);
    }
}

#[test]
fn test_non_blocking_input() {
    let should_pass = vec![
        "SELECT * FROM users WHERE id = 1",
        "SELECT id, name FROM users WHERE status = 'active'",
        "SELECT COUNT(*) FROM orders WHERE created_at > '2024-01-01'",
    ];

    for query in &should_pass {
        assert!(!is_query_malicious(query), "Should pass: {}", query);
    }
}
