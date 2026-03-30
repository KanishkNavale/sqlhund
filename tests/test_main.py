import pytest


from injectdb import is_query_malicious

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
