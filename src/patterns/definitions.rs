pub const GENERAL: &[&str] = &[
    // UNION-BASED ATTACKS
    // Matches: UNION SELECT, UNION ALL SELECT, UNION DISTINCT SELECT
    r"(?i)\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
    // STACKED QUERIES
    // Matches: ; SELECT, ; DROP, ; INSERT, ; UPDATE, ; DELETE, etc.
    r"(?i);\s*\b(?:select|insert|update|delete|drop|create|alter|truncate|exec|execute|call|begin|commit|rollback)\b",
    // SQL LINE & BLOCK COMMENTS (evasion via comment injection)
    // Matches: -- comment, # comment (MySQL style), /* block */
    // False-positive risk: "--" appears in natural language. Accept for security contexts.
    r"(?m)(--[^\r\n]*$|#[^\r\n]*$)|(/\*[\s\S]*?\*/)",
    // TAUTOLOGIES (boolean bypass)
    // Matches: OR 'a'='a', AND 1=1, OR true, OR 1 -- etc.
    r#"(?i)[\d)'"]\s+\b(?:OR|AND)\b[\s\t\r\n/*]+(?:'[^']*'?\s*=\s*'?[^'\s]*'?|"[^"]*"?\s*=\s*"?[^"\s]*"?|\d+\s*=\s*\d+|\btrue\b|\bfalse\b)"#,
    // ALWAYS-TRUE / ALWAYS-FALSE SHORTCUTS
    // Matches: OR 1, AND 0, OR (1), etc. — simpler tautology forms
    r#"(?i)[\d)'"]\s+\b(?:OR|AND)\s+\d+\s*(?:[=<>!]|--|$|\))"#,
    // DDL (Data Definition Language)
    // Matches: DROP TABLE, CREATE INDEX, ALTER VIEW, TRUNCATE TRIGGER, etc.
    r"(?i)\b(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|INDEX|VIEW|TRIGGER|SCHEMA|DATABASE|SEQUENCE|PROCEDURE|FUNCTION|ROLE|USER)\b",
    // DML (Data Manipulation Language)
    // Matches: DELETE FROM, INSERT INTO, UPDATE ... SET, REPLACE INTO, MERGE INTO
    r#"(?i)\b(?:DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+[\w`"'\[]+[\w`"'\]]*\s+SET|REPLACE\s+INTO|MERGE\s+INTO)\b"#,
    // PERMISSIONS & EXECUTION
    // Matches: EXEC foo, EXECUTE bar, CALL proc, GRANT ..., REVOKE ...
    r"(?i)\b(?:EXEC|EXECUTE)\s+\w*_\w+\s*\(|\bCALL\s+\w*_\w+\s*\(|\b(?:GRANT|REVOKE)\b",
    // HEX / BINARY LITERALS
    // Matches: 0x1A2B, X'41424344'
    r"(?i)\b0x[0-9a-f]+\b|[Xx]'(?:[0-9a-fA-F]{2})+'",
    // URL / PERCENT-ENCODED METACHARACTERS
    // Matches: %27 ('), %22 ("), %3b (;), %2d (-), %23 (#), %2f (/), %00 (null)
    r"(?i)%(27|22|3[bB]|2[dD]|23|2[fF]|00)|\x00",
    // INFORMATION SCHEMA PROBING
    // Matches: information_schema.tables, information_schema.columns, etc.
    r"(?i)\binformation_schema\b",
    // SUBQUERY INJECTION
    // Matches: SELECT inside parentheses — classic subquery or scalar injection
    r"(?i)\(\s*select\s+",
    // BLIND TIME-DELAY ATTACKS (generic forms)
    // Matches: SLEEP(n), WAITFOR DELAY, PG_SLEEP(n), BENCHMARK(n,expr)
    r"(?i)\b(?:sleep|pg_sleep|waitfor[\s\t]+delay|benchmark)\s*\(",
    // CASE-BASED BLIND INJECTION
    // Matches: CASE WHEN (condition) THEN ... ELSE ... END
    r"(?i)\bcase\s+when\s+.+?\s+then\b",
    // DDL — any schema modification
    r"(?i)\b(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|INDEX|VIEW|TRIGGER|SCHEMA|DATABASE|SEQUENCE|PROCEDURE|FUNCTION|ROLE|USER)\b",
    // DML — any data modification
    r#"(?i)\b(?:DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+[\w`"'\[]+[\w`"'\]]*\s+SET|REPLACE\s+INTO|MERGE\s+INTO)\b"#,
    // UNION — column count probing / data exfiltration
    r"(?i)\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
    // SUBQUERIES — nested SELECT
    r"(?i)\(\s*select\s+",
    // STACKED QUERIES — multiple statements
    r"(?i);\s*\b(?:select|insert|update|delete|drop|create|alter|truncate|exec|execute|call|begin|commit|rollback)\b",
    // COMMENTS — used to truncate or bypass
    r"(?m)(--[^\r\n]*$|#[^\r\n]*$)|(/\*[\s\S]*?\*/)",
    // EXECUTION
    r"(?i)\b(?:EXEC|EXECUTE)\s+\w*_\w+\s*\(|\bCALL\s+\w*_\w+\s*\(|\b(?:GRANT|REVOKE)\b",
];

pub const SQLITE: &[&str] = &[
    // SYSTEM SCHEMA ACCESS
    // Matches: sqlite_master, sqlite_schema, sqlite_temp_master, sqlite_temp_schema
    r"(?i)\bsqlite_(?:master|temp_master|schema|temp_schema)\b",
    // DANGEROUS BUILT-IN FUNCTIONS
    // Matches: load_extension(...), writefile(...), readfile(...), randomblob(...),
    //          sqlite_version(...), char(...), hex(...)
    r"(?i)\b(?:load_extension|writefile|readfile|randomblob|sqlite_version|char|hex)\s*\(",
    // DATABASE ADMINISTRATION
    // Matches: ATTACH DATABASE, DETACH <alias>, PRAGMA <setting>
    r"(?i)\bATTACH\b\s+DATABASE\b|\bDETACH\b\s+\w+|\bPRAGMA\b\s+\w+",
    // TEMP TABLE / SCHEMA MANIPULATION
    // Matches: CREATE TEMP TABLE, CREATE TEMPORARY VIEW, etc.
    r"(?i)\bcreate\s+te?mp(?:orary)?\s+(?:table|view|trigger)\b",
    // VIRTUAL TABLE ABUSE
    // Matches: CREATE VIRTUAL TABLE ... USING fts5/rtree/etc.
    r"(?i)\bcreate\s+virtual\s+table\b",
    // SQLITE INTERNAL FUNCTIONS (fingerprinting / exfil)
    // Matches: sqlite_compileoption_get, sqlite_compileoption_used
    r"(?i)\bsqlite_compileoption_(?:get|used)\s*\(",
    // GLOB / LIKE pattern injection
    // Matches: GLOB keyword used standalone (not part of normal queries)
    r"(?i)\bglob\s*\(",
    // ZEROBLOB abuse
    // Matches: zeroblob(n) — can be used for OOM/DoS
    r"(?i)\bzeroblob\s*\(",
    // INLINE VIEW / RECURSIVE CTE
    // Matches: WITH RECURSIVE — used in complex blind injections
    r"(?i)\bwith\s+recursive\b",
];

pub const POSTGRES: &[&str] = &[
    // SYSTEM CATALOG PROBING
    // Matches: pg_catalog.*, pg_tables, pg_class, pg_namespace, etc.
    r"(?i)\bpg_catalog\b|\bpg_(?:tables|class|namespace|attribute|proc|user|roles|settings|indexes|stat_\w+)\b",
    // FILE SYSTEM ACCESS FUNCTIONS
    // Matches: pg_read_file(), pg_read_binary_file(), pg_ls_dir(), pg_stat_file()
    r"(?i)\bpg_(?:read_file|read_binary_file|ls_dir|stat_file|write_file)\s*\(",
    // LARGE OBJECT (LOB) FILE READ/WRITE
    // Matches: lo_import(...), lo_export(...), lo_get(...)
    r"(?i)\blo_(?:import|export|get|put|unlink|open|read|write|lseek|close|creat|create|truncate)\s*\(",
    // COPY TO/FROM FILE (arbitrary file read/write as superuser)
    // Matches: COPY table TO '/etc/passwd', COPY ... FROM PROGRAM '...'
    r"(?i)\bcopy\b[\s\S]{0,200}\b(?:to|from)\b\s*(?:'[^']*'|program\b)",
    // DBLINK / CROSS-SERVER EXECUTION
    // Matches: dblink(...), dblink_exec(...), dblink_connect(...)
    r"(?i)\bdblink(?:_exec|_connect|_disconnect|_open|_fetch|_close|_get_connections|_cancel_query|_error_message)?\s*\(",
    // DOLLAR-QUOTING (evasion technique / anonymous blocks)
    // Matches: $$...$$, $tag$...$tag$
    r"\$[^$]*\$",
    // ANONYMOUS DO BLOCKS
    // Matches: DO $$ BEGIN ... END $$; — arbitrary PL/pgSQL execution
    r"(?i)\bdo\s+(?:\$[^$]*\$|')",
    // EXTENSION LOADING
    // Matches: CREATE EXTENSION <name> — can load dangerous extensions
    r"(?i)\bcreate\s+extension\b",
    // SERVER CONFIGURATION MANIPULATION
    // Matches: ALTER SYSTEM SET <param> — persists config changes
    r"(?i)\balter\s+system\s+set\b",
    // CAST OPERATOR ABUSE (type confusion)
    // Matches: ::text, ::integer, ::bytea — PostgreSQL-specific cast syntax
    r"::\s*\w+",
    // SERVER-SIDE FUNCTION EXECUTION
    // Matches: pg_sleep(), pg_cancel_backend(), pg_terminate_backend()
    r"(?i)\bpg_(?:sleep|cancel_backend|terminate_backend|reload_conf|rotate_logfile)\s*\(",
    // SYSTEM INFO FUNCTIONS (fingerprinting)
    // Matches: version(), current_database(), current_user, inet_server_addr(), etc.
    r"(?i)\b(?:version|current_database|current_schema|inet_server_addr|inet_server_port|pg_postmaster_start_time|pg_conf_load_time)\s*\(\s*\)",
    // GENERATE_SERIES ABUSE (timing / row flooding)
    // Matches: generate_series(1, 1000000)
    r"(?i)\bgenerate_series\s*\(",
    // FORMAT STRING INJECTION
    // Matches: format('%s', ...) — used to build dynamic SQL
    r"(?i)\bformat\s*\(\s*'[^']*%[^']*'",
    // RETURNING CLAUSE (data exfiltration from DML)
    // Matches: INSERT ... RETURNING, DELETE ... RETURNING, UPDATE ... RETURNING
    r"(?i)\breturning\s+[\w\*]",
    // PRIVILEGE ESCALATION VIA ROLE
    // Matches: SET ROLE, SET SESSION AUTHORIZATION
    r"(?i)\bset\s+(?:role|session\s+authorization)\b",
];

pub const DUCKDB: &[&str] = &[
    // SYSTEM TABLE PROBING
    // Matches: duckdb_tables(), duckdb_columns(), duckdb_schemas(), etc.
    r"(?i)\bduckdb_(?:tables|columns|schemas|databases|types|functions|settings|extensions|views|indexes|sequences|constraints|keywords|optimizers)\s*\(",
    // FILE SYSTEM ACCESS
    // Matches: read_csv(), read_parquet(), read_json(), read_text(), read_blob()
    r"(?i)\bread_(?:csv|csv_auto|parquet|json|json_auto|text|blob)\s*\(",
    // FILE EXPORT
    // Matches: COPY ... TO 'file', EXPORT DATABASE
    r"(?i)\bcopy\b[\s\S]{0,200}\bto\b\s*'[^']*'",
    r"(?i)\bexport\s+database\b",
    // EXTERNAL DATABASE ATTACH
    // Matches: ATTACH 'file.db', ATTACH DATABASE
    r"(?i)\battach\b\s*(?:database\b\s*)?'[^']*'",
    // HTTPFS / REMOTE FILE ACCESS
    // Matches: read_csv('https://...'), read_parquet('s3://...')
    r"(?i)\bread_\w+\s*\(\s*'(?:https?|s3|gcs|az)://",
    // GLOB FILE ENUMERATION
    // Matches: glob('path/*')
    r"(?i)\bglob\s*\(\s*'[^']*'",
    // SECRETS (credential exfiltration)
    // Matches: CREATE SECRET, WHICH_SECRET(), duckdb_secrets()
    r"(?i)\bcreate\s+(?:or\s+replace\s+)?secret\b",
    r"(?i)\bduckdb_secrets\s*\(",
    // PRAGMA / EXTENSION LOADING
    // Matches: LOAD 'extension', INSTALL 'extension'
    r"(?i)\b(?:load|install)\s+'[^']*'",
    // MACRO / FUNCTION INJECTION
    // Matches: CREATE MACRO, CREATE FUNCTION
    r"(?i)\bcreate\s+(?:or\s+replace\s+)?(?:macro|function)\b",
    // SUMMARIZE / DESCRIBE (schema probing)
    // Matches: SUMMARIZE table, DESCRIBE table
    r"(?i)\b(?:summarize|describe)\s+\w+",
    // RECURSIVE CTE
    // Matches: WITH RECURSIVE — used in blind injection
    r"(?i)\bwith\s+recursive\b",
];
