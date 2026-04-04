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

    This analyzer detects patterns from OWASP Top 10 A03:2021 - Injection, providing
    dual-axis classification using CWE (technique vs impact) and CAPEC attack patterns.

    Args:
        query (str): The SQL query to analyze.

    Returns:
        dict: A dictionary containing the analysis results, including:
            - 'is_malicious' (bool): Whether the query is potentially malicious.
            - 'matches' (dict): Matched patterns grouped by database, where each database key maps to a list of pattern objects.
              Each pattern object contains:
                - 'technique' (list[str]): CWE identifiers describing HOW the attack is delivered (e.g., ['CWE-89', 'CWE-610']).
                - 'impact' (list[str]): CWE identifiers describing WHAT the attacker achieves (e.g., ['CWE-200', 'CWE-285']).
                - 'capec' (list[int]): CAPEC attack pattern IDs (e.g., [66, 470]).

    Example:
        >>> import sqlhund
        >>> sqlhund.analyze_query("SELECT * FROM users; DROP TABLE users")
        {
            'is_malicious': True,
            'matches': {
                'general': [
                    {
                        'technique': ['CWE-89'],
                        'impact': ['CWE-285', 'CWE-471'],
                        'capec': [66]
                    }
                ]
            }
        }
        >>> sqlhund.analyze_query("SELECT load_extension('evil')")
        {
            'is_malicious': True,
            'matches': {
                'sqlite': [
                    {
                        'technique': ['CWE-89', 'CWE-610', 'CWE-114'],
                        'impact': ['CWE-200', 'CWE-285'],
                        'capec': [470]
                    }
                ]
            }
        }
        >>> sqlhund.analyze_query("SELECT id FROM users WHERE id = 1")
        {
            'is_malicious': False,
            'matches': {}
        }
    """
    ...
