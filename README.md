<h1 align="center">sqlhund</h1>

<p align="center">
<em>Rust-powered auditable SQL injection detection for Python 🐍. Built for AI agents ✨.</em>
</p>

<p align="center">
<a href="https://pypi.org/project/sqlhund/"><img src="https://img.shields.io/pypi/v/sqlhund?color=%2334D058&label=pypi" alt="PyPI"></a>
<a href="https://pypi.org/project/sqlhund/"><img src="https://img.shields.io/pypi/pyversions/sqlhund" alt="Python versions"></a>
<a href="https://github.com/KanishkNavale/sqlhund/blob/main/LICENSE"><img src="https://img.shields.io/github/license/KanishkNavale/sqlhund" alt="License"></a>
<a href="https://github.com/KanishkNavale/sqlhund/actions/workflows/ci.yml"><img src="https://github.com/KanishkNavale/sqlhund/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/KanishkNavale/sqlhund/actions/workflows/codeql.yml"><img src="https://github.com/KanishkNavale/sqlhund/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
</p>

---

**sqlhund** detects SQL injection patterns with CWE and CAPEC classification. Written in Rust with Python bindings via [PyO3](https://pyo3.rs/), it provides security analysis for AI agents that generate or relay SQL queries, preventing database manipulation through dual-axis threat intelligence (technique vs impact).

```python
>>> import sqlhund
>>> sqlhund.is_query_malicious("SELECT * FROM users WHERE id = 1")
False
>>> sqlhund.is_query_malicious("' OR 1=1 --")
True
```

> [!NOTE]
>
> The primary goal is to prevent AI agents from manipulating data in or the structure of your database.

## Installation

```bash
pip install sqlhund  # pip
poetry add sqlhund   # poetry
uv add sqlhund       # uv
```

Requires Python 3.10+. No runtime dependencies.

## Quick Start

sqlhund exposes two functions — that's the entire API:

```python
import sqlhund

# Simple boolean check
sqlhund.is_query_malicious("SELECT * FROM users; DROP TABLE users")
# True

# Detailed analysis with security classification
result = sqlhund.analyze_query("SELECT * FROM users; DROP TABLE users")
# {
#     'is_malicious': True,
#     'matches': {
#         'general': [
#             {
#                 'technique': ['CWE-89'],           # HOW: SQL Injection
#                 'impact': ['CWE-285', 'CWE-471'],  # WHAT: Auth bypass + data tampering
#                 'capec': [66]                      # CAPEC-66: SQL Injection
#             }
#         ]
#     }
# }

# File operation attacks detected
result = sqlhund.analyze_query("SELECT load_extension('evil')")
# {
#     'is_malicious': True,
#     'matches': {
#         'sqlite': [
#             {
#                 'technique': ['CWE-89', 'CWE-610', 'CWE-114'],
#                 'impact': ['CWE-200', 'CWE-285'],
#                 'capec': [470]
#             }
#         ]
#     }
# }

# Safe queries pass through cleanly
sqlhund.analyze_query("SELECT id FROM users WHERE id = 1")
# {'is_malicious': False, 'matches': {}}
```

## Usage Examples

### Validating AI-Generated SQL

```python
import sqlhund

def execute_ai_query(query: str):
    """Execute AI-generated SQL with injection protection."""
    if sqlhund.is_query_malicious(query):
        raise ValueError("Potential SQL injection detected")

    # Safe to execute
    return database.execute(query)
```

### Detailed Threat Analysis

```python
result = sqlhund.analyze_query("SELECT * FROM users WHERE id = 1 OR 1=1")

if result['is_malicious']:
    for db_name, patterns in result['matches'].items():
        print(f"Database: {db_name}")
        for pattern in patterns:
            print(f"  Technique: {pattern['technique']}")  # CWE-89
            print(f"  Impact: {pattern['impact']}")        # CWE-285
            print(f"  CAPEC: {pattern['capec']}")          # 66
```

### Pre-screening an User Input

```python
def sanitize_search_query(user_input: str) -> str:
    """Validate search input before building SQL."""
    test_query = f"SELECT * FROM products WHERE name LIKE '%{user_input}%'"

    if sqlhund.is_query_malicious(test_query):
        raise ValueError("Invalid search term")

    return user_input
```

## Features

- **Fast**: Core detection engine written in Rust, compiled to a native Python extension
- **Accurate**: 100% precision and recall on a 10M+ query benchmark (zero false positives, zero false negatives)
- **Multi-database**: Detects injection patterns targeting SQLite, PostgreSQL, and DuckDB
- **Zero dependencies**: Ships as a self-contained native wheel
- **AI-agent ready**: Designed as a guardrail for LLM-generated SQL
- **Security classification**: Maps detected patterns to CWE and CAPEC taxonomies for threat intelligence

## Security Classification

sqlhund classifies detected patterns using industry-standard security frameworks:

### Dual-Axis CWE Analysis

Analyze each detected pattern across two independent axes:

- **Technique** (HOW): CWE identifiers describing the injection mechanism
  - CWE-89: SQL Injection
  - CWE-610: External Resource Reference (file operations)
  - CWE-94/95: Code/Eval Injection
  - CWE-77/78: Command/OS Command Injection
  - CWE-114: Process Control (loading untrusted libraries)
  - CWE-116/184: Encoding evasion and filter bypass

- **Impact** (WHAT): CWE identifiers describing the attack consequences
  - CWE-200: Information Disclosure
  - CWE-285: Authorization Bypass
  - CWE-269: Privilege Escalation
  - CWE-471: Data Tampering
  - CWE-400: Resource Exhaustion (DoS)
  - CWE-208: Timing Side-Channel (blind injection)
  - CWE-497: System Information Exposure

### CAPEC Attack Patterns

Matches are also mapped to [CAPEC](https://capec.mitre.org/) attack pattern IDs:

- **CAPEC-66**: SQL Injection
- **CAPEC-7**: Blind SQL Injection
- **CAPEC-54**: Query System for Information
- **CAPEC-470**: Expanding Control over the OS from the Database
- **CAPEC-664**: Server-Side Request Forgery

### OWASP Alignment

sqlhund detects patterns from [OWASP Top 10 A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/), covering:

- SQL Injection (CWE-89)
- Command Injection (CWE-77, CWE-78)
- Code Injection (CWE-94, CWE-95)
- File/Resource Injection (CWE-610)

**Resources:**

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [OWASP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CAPEC-66: SQL Injection](https://capec.mitre.org/data/definitions/66.html)

## Supported Databases

sqlhund detects database-specific injection patterns for:

| Database   | Detection Patterns |
|------------|--------------------|
| General    | ✓ UNION, comments, tautologies, subqueries, time delays |
| SQLite     | ✓ load_extension, ATTACH, PRAGMA, virtual tables |
| PostgreSQL | ✓ pg_read_file, COPY, DO blocks, dblink, extensions |
| DuckDB     | ✓ read_csv, ATTACH, httpfs, CREATE SECRET, macros |

## Benchmarks

Evaluated against the [RbSQLi dataset](https://data.mendeley.com/datasets/xz4d5zj5yw/3) — 10,304,026 labeled SQL queries (2,813,146 malicious, 7,490,880 benign).

|                      | Predicted Malicious | Predicted Benign |
|----------------------|--------------------:|-----------------:|
| **Actual Malicious** |       2,813,146     |                0 |
| **Actual Benign**    |                   0 |        7,490,880 |

Precision: 100% · Recall: 100% · Accuracy: 100%

## Building from Source

Requires [Rust](https://rustup.rs/), [Maturin](https://github.com/PyO3/maturin), and [uv](https://docs.astral.sh/uv/).

```shell
git clone https://github.com/KanishkNavale/sqlhund
cd sqlhund
make dev         # set up development environment
make build       # compile debug build
make release     # compile optimized release build
```

## Testing

Run unit tests (Rust + Python):

```shell
make unittest
```

Run evaluation against the full RbSQLi dataset (download [the dataset](https://data.mendeley.com/datasets/xz4d5zj5yw/3), place it at `tests/data/wild.csv`):

```shell
make wildtest
```

## Contributing

Contributions are welcome. See the [open issues](https://github.com/KanishkNavale/sqlhund/issues) or submit a pull request.

## License

The [MIT License](LICENSE) licenses this project.
