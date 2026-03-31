import pytest

from sqlhund import is_query_malicious, analyze_query

should_block = [
    "DELETE FROM users",
    "INSERT INTO users (id) VALUES (1)",
    "UPDATE users SET name = 'x' WHERE id = 1",
    "SELECT * FROM (SELECT id FROM users)",
    "SELECT a FROM t UNION SELECT b FROM t2",
    "SELECT * FROM users; DROP TABLE users",
    "SELECT * FROM users WHERE id = 1 OR 1=1",
]

should_pass = [
    "SELECT * FROM users WHERE id = 1",
    "SELECT id, name FROM users WHERE status = 'active'",
    "SELECT COUNT(*) FROM orders WHERE created_at > '2024-01-01'",
]


@pytest.mark.parametrize("query", should_block)
def test_should_block(query):
    assert is_query_malicious(query), f"Should be blocked: {query}"


@pytest.mark.parametrize("query", should_pass)
def test_should_pass(query):
    assert not is_query_malicious(query), f"Should pass: {query}"


@pytest.mark.parametrize("query", should_block)
def test_analyze_query_malicious(query):
    analysis = analyze_query(query)
    assert analysis["is_malicious"], f"Should be malicious: {query}"
    assert (
        len(analysis["affected_databases"]) > 0
    ), f"Affected databases should not be empty: {query}"


@pytest.mark.parametrize("query", should_pass)
def test_analyze_query_non_malicious(query):
    analysis = analyze_query(query)
    assert not analysis["is_malicious"], f"Should not be malicious: {query}"
    assert (
        len(analysis["affected_databases"]) == 0
    ), f"Affected databases should be empty: {query}"
