<h1 align="center">sqlhund</h1>

<p align="center">
<em>Rust-powered SQL injection detection for Python 🐍. Built for AI agents ✨.</em>
</p>

<p align="center">
<a href="https://pypi.org/project/sqlhund/"><img src="https://img.shields.io/pypi/v/sqlhund?color=%2334D058&label=pypi" alt="PyPI"></a>
<a href="https://pypi.org/project/sqlhund/"><img src="https://img.shields.io/pypi/pyversions/sqlhund" alt="Python versions"></a>
<a href="https://github.com/KanishkNavale/sqlhund/blob/main/LICENSE"><img src="https://img.shields.io/github/license/KanishkNavale/sqlhund" alt="License"></a>
<a href="https://github.com/KanishkNavale/sqlhund/actions/workflows/ci.yml"><img src="https://github.com/KanishkNavale/sqlhund/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/KanishkNavale/sqlhund/actions/workflows/codeql.yml"><img src="https://github.com/KanishkNavale/sqlhund/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
</p>

---

**sqlhund** detects SQL injection patterns in input strings super fast 🚀. Written in Rust with Python bindings via [PyO3](https://pyo3.rs/) & designed to guard AI agents that generate or relay SQL queries from manipulating your database.

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
pip install sqlhund  # if using pip
poetry add sqlhund   # if using Poetry
uv add sqlhund       # if using UV
```

Requires Python 3.10+. No runtime dependencies.

## Quick Start

sqlhund exposes two functions — that's the entire API:

```python
import sqlhund

# Simple boolean check
sqlhund.is_query_malicious("SELECT * FROM users; DROP TABLE users")
# True

# Detailed analysis with affected databases
sqlhund.analyze_query("SELECT * FROM users; DROP TABLE users")
# {'is_malicious': True, 'affected_databases': ['sqlite', 'duckdb', 'postgresql']}

# Safe queries pass through cleanly
sqlhund.analyze_query("SELECT id FROM users WHERE id = 1")
# {'is_malicious': False, 'affected_databases': []}
```

## Features

- **Fast**: Core detection engine written in Rust, compiled to a native Python extension
- **Accurate**: 100% precision and recall on a 10M+ query benchmark (zero false positives, zero false negatives)
- **Minimal API**: Two functions: `is_query_malicious()` and `analyze_query()`
- **Multi-database**: Detects injection patterns targeting SQLite, PostgreSQL, and DuckDB
- **Zero dependencies**: Ships as a self-contained native wheel
- **AI-agent ready**: Designed as a guardrail for LLM-generated SQL

## Supported Databases

| Database   | Detection |
|------------|-----------|
| SQLite     | ✓         |
| PostgreSQL | ✓         |
| DuckDB     | ✓         |

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
make release   # compile optimized release build
```

## Testing

Run unit tests (Rust + Python):

```shell
make unittest
```

Run evaluation against the full RbSQLi dataset (download [the dataset](https://data.mendeley.com/datasets/xz4d5zj5yw/3), place it at `tests/data/wild.csv`):

```console
make wildtest
```

## Contributing

Contributions are welcome. See the [open issues](https://github.com/KanishkNavale/sqlhund/issues) or submit a pull request.

## License

The [MIT License](LICENSE) licenses this project.
