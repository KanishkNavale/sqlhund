def is_query_malicious(query: str) -> bool:
    """
    Checks whether the input string contains SQL injection patterns.

    Args:
        query (str): The input string to validate.

    Returns:
        bool: True if an injection pattern is detected, False otherwise.

    Example:
        >>> import sqlhund
        >>> sqlhund.is_query_malicious("' OR 1=1 --")
        True
        >>> sqlhund.is_query_malicious("SELECT id FROM users WHERE id = 1")
        False
    """
    ...

def analyze_query(query: str) -> dict:
    """
    Audits the input SQL query for potential injection patterns and returns a detailed report.

    Args:
        query (str): The SQL query to analyze.

    Returns:
        dict: A dictionary containing the analysis results, including:
            - 'is_malicious' (bool): Whether the query is potentially malicious.
            - 'affected_databases' (list): A list of databases affected by the detected injection patterns.

    Example:
        >>> import sqlhund
        >>> sqlhund.analyze_query("SELECT * FROM users; DROP TABLE users")
        {
            'is_malicious': True,
            'affected_databases': ['sqlite', 'duckdb', 'postgresql']
        }
        >>> sqlhund.analyze_query("SELECT id FROM users WHERE id = 1")
        {
            'is_malicious': False,
            'affected_databases': []
        }
    """
    ...
