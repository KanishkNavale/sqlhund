def check_malicious(query: str) -> bool:
    """
    Checks whether the input string contains SQL injection patterns.

    Args:
        query (str): The input string to validate.

    Returns:
        bool: True if an injection pattern is detected, False otherwise.

    Example:
        >>> import injectdb
        >>> injectdb.check_malicious("' OR 1=1 --")
        True
        >>> injectdb.check_malicious("SELECT id FROM users WHERE id = 1")
        False
    """
    ...
