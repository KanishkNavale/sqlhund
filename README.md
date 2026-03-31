# injectdb

[![CodeQL](https://github.com/KanishkNavale/injectdb/actions/workflows/codeql.yml/badge.svg)](https://github.com/KanishkNavale/injectdb/actions/workflows/codeql.yml)   [![Dependabot Updates](https://github.com/KanishkNavale/injectdb/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/KanishkNavale/injectdb/actions/workflows/dependabot/dependabot-updates) [![Dependency Review](https://github.com/KanishkNavale/injectdb/actions/workflows/dependecy-review.yml/badge.svg)](https://github.com/KanishkNavale/injectdb/actions/workflows/dependecy-review.yml)    [![Release](https://github.com/KanishkNavale/injectdb/actions/workflows/release.yml/badge.svg)](https://github.com/KanishkNavale/injectdb/actions/workflows/release.yml)    [![Test, Lint & Format](https://github.com/KanishkNavale/injectdb/actions/workflows/ci.yml/badge.svg)](https://github.com/KanishkNavale/injectdb/actions/workflows/ci.yml)

A Rust library with Python bindings for detecting SQL injection patterns in input strings. Built for speed and designed especially for AI agents that process or generate SQL queries.

>[!NOTE]
>
>The primary goal is to block AI agents from manipulating the data in the DB. or the DB. itself!

## Supported Databases

- Sqlite
- Postgres
- DuckDB

## Building from Source

Requires [Rust](https://rustup.rs/), [Maturin](https://github.com/PyO3/maturin) & [UV](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/kanishknavale/injectdb
cd injectdb
pip install maturin
make release
```

## Testing

- Sanity Tests

    ```bash
    make unittest
    ```

- Dataset evaluation (requires dataset)

    Download the [RbSQLi dataset](https://data.mendeley.com/datasets/xz4d5zj5yw/3) and place it at `tests/data/wild.csv`, then run:

    ```bash
    make test-wild
    ```

## Benchmarks

Evaluated against the [RbSQLi dataset](https://data.mendeley.com/datasets/xz4d5zj5yw/3) containing 10,304,026 labeled SQL queries (2,813,146 malicious, 7,490,880 benign).

- Confusion Matrix

    Actual \ Predicted |   Malicious   |     Benign    |
    -------------------|---------------|---------------|
    Actual Malicious   |   2,813,146   |           0   |
    Actual Benign      |           0   |   7,490,880   |
