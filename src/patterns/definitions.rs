//! SQL injection pattern detection rules.
//!
//! Each [`PatternEntry`] classifies a regex across two independent CWE axes
//! and one CAPEC axis, so consumers can filter and triage detections by
//! *how* an attack arrives as well as *what* it achieves.
//!
//! # CWE axes
//!
//! | Field | Question answered | Always contains |
//! |-------|-------------------|-----------------|
//! | [`PatternEntry::technique`] | How is the attack delivered? | [`CWE::CWE89`] + any evasion/delivery CWEs |
//! | [`PatternEntry::impact`]    | What does the attacker gain? | One or more consequence CWEs |
//!
//! # CAPEC IDs used in this module
//!
//! | ID  | Name |
//! |-----|------|
//! | 7   | Blind SQL Injection |
//! | 54  | Query System for Information |
//! | 66  | SQL Injection |
//! | 470 | Expanding Control over the OS from the Database |
//! | 664 | Server-Side Request Forgery |
//!
//! # Required CWE variants
//!
//! The following variants must be present in [`crate::patterns::abstracts::CWE`]:
//!
//! **Technique CWEs**
//! - `CWE77`  — Command Injection
//! - `CWE78`  — OS Command Injection
//! - `CWE89`  — SQL Injection
//! - `CWE94`  — Code Injection
//! - `CWE95`  — Eval Injection
//! - `CWE114` — Process Control (loading untrusted native libraries)
//! - `CWE116` — Improper Encoding or Escaping of Output (evasion via encoding)
//! - `CWE184` — Incomplete List of Disallowed Inputs (filter bypass)
//! - `CWE610` — Externally Controlled Reference to a Resource in Another Sphere
//!
//! **Impact CWEs**
//! - `CWE200` — Exposure of Sensitive Information to an Unauthorized Actor
//! - `CWE208` — Observable Timing Discrepancy (blind/timing side-channel)
//! - `CWE269` — Improper Privilege Management
//! - `CWE285` — Improper Authorization
//! - `CWE400` — Uncontrolled Resource Consumption
//! - `CWE471` — Modification of Assumed-Immutable Data
//! - `CWE497` — Exposure of Sensitive System Information to an Unauthorized Control Sphere

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Database {
    General,
    Sqlite,
    Postgres,
    DuckDb,
}

impl Database {
    pub fn as_str(&self) -> &'static str {
        match self {
            Database::General => "general",
            Database::Sqlite => "sqlite",
            Database::Postgres => "postgres",
            Database::DuckDb => "duckdb",
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum CWE {
    CWE74, // Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')
    CWE77, // Improper Neutralization of Special Elements used in a Command ('Command Injection')
    CWE78, // Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
    CWE89, // Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
    CWE94, // Improper Control of Generation of Code ('Code Injection')
    CWE95, // Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    CWE114, // Uncontrolled Process Control (loading untrusted native libraries)
    CWE116, // Improper Encoding or Escaping of Output
    CWE184, // Incomplete List of Disallowed Inputs
    CWE200, // Exposure of Sensitive Information to an Unauthorized Actor
    CWE208, // Observable Timing Discrepancy
    CWE269, // Improper Privilege Management
    CWE285, // Improper Authorization
    CWE400, // Uncontrolled Resource Consumption
    CWE471, // Modification of Assumed-Immutable Data
    CWE497, // Exposure of Sensitive System Information to an Unauthorized Control Sphere
    CWE610, // Externally Controlled Reference to a Resource in Another Sphere
}

impl CWE {
    pub fn as_str(&self) -> &'static str {
        match self {
            CWE::CWE74 => "CWE-74",
            CWE::CWE77 => "CWE-77",
            CWE::CWE78 => "CWE-78",
            CWE::CWE89 => "CWE-89",
            CWE::CWE94 => "CWE-94",
            CWE::CWE95 => "CWE-95",
            CWE::CWE114 => "CWE-114",
            CWE::CWE116 => "CWE-116",
            CWE::CWE184 => "CWE-184",
            CWE::CWE200 => "CWE-200",
            CWE::CWE208 => "CWE-208",
            CWE::CWE269 => "CWE-269",
            CWE::CWE285 => "CWE-285",
            CWE::CWE400 => "CWE-400",
            CWE::CWE471 => "CWE-471",
            CWE::CWE497 => "CWE-497",
            CWE::CWE610 => "CWE-610",
        }
    }
}

#[derive(Debug)]
pub struct PatternEntry {
    /// The regex pattern matched against user-supplied input.
    pub pattern: &'static str,

    /// CWEs describing *how* the attack is delivered (the injection mechanism).
    ///
    /// Always contains at least [`CWE::CWE89`]. Additional entries are present
    /// when the pattern also represents a distinct delivery mechanism such as
    /// encoding evasion ([`CWE::CWE116`], [`CWE::CWE184`]), file-resource
    /// reference ([`CWE::CWE610`]), or code/command injection
    /// ([`CWE::CWE77`], [`CWE::CWE78`], [`CWE::CWE94`], [`CWE::CWE95`],
    /// [`CWE::CWE114`]).
    pub technique: &'static [CWE],

    /// CWEs describing *what* the attacker achieves beyond the SQL layer.
    ///
    /// Examples: data disclosure ([`CWE::CWE200`], [`CWE::CWE497`]),
    /// authorization bypass ([`CWE::CWE285`]), privilege escalation
    /// ([`CWE::CWE269`]), data tampering ([`CWE::CWE471`]),
    /// resource exhaustion ([`CWE::CWE400`]), or timing side-channel
    /// ([`CWE::CWE208`]).
    pub impact: &'static [CWE],

    /// [CAPEC](https://capec.mitre.org/) attack-pattern IDs for threat-model
    /// cross-referencing. See the module-level documentation for the full
    /// table of IDs used here.
    pub capec: &'static [u32],
}

impl PatternEntry {
    /// Creates a new [`PatternEntry`].
    ///
    /// Prefer the constants defined in this module over constructing entries
    /// at runtime; the `const fn` qualifier allows these to live in `.rodata`.
    pub const fn new(
        pattern: &'static str,
        technique: &'static [CWE],
        impact: &'static [CWE],
        capec: &'static [u32],
    ) -> Self {
        Self {
            pattern,
            technique,
            impact,
            capec,
        }
    }
}

/// Dialect-agnostic SQL injection patterns applicable to any relational database.
pub const GENERAL: &[PatternEntry] = &[
    // UNION-based exfiltration — column-count probing to read arbitrary rows.
    PatternEntry::new(
        r"(?i)\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
        &[CWE::CWE89],
        &[CWE::CWE200],
        &[66],
    ),
    // Stacked queries — semicolon-delimited statements enabling arbitrary DML/DDL.
    PatternEntry::new(
        r"(?i);\s*\b(?:select|insert|update|delete|drop|create|alter|truncate|exec|execute|call|begin|commit|rollback)\b",
        &[CWE::CWE89],
        &[CWE::CWE285, CWE::CWE471],
        &[66],
    ),
    // Comment injection — truncates or rewrites query logic to bypass filters.
    // CWE-184: the incomplete blocklist that the comment syntax evades.
    PatternEntry::new(
        r"(?m)(--[^\r\n]*$|#[^\r\n]*$)|(/\*[\s\S]*?\*/)",
        &[CWE::CWE89, CWE::CWE184],
        &[CWE::CWE285],
        &[66],
    ),
    // Tautologies — always-true boolean conditions bypassing WHERE clauses.
    PatternEntry::new(
        r#"(?i)[\d)'"]\s+\b(?:OR|AND)\b[\s\t\r\n/*]+(?:'[^']*'?\s*=\s*'?[^'\s]*'?|"[^"]*"?\s*=\s*"?[^"\s]*"?|\d+\s*=\s*\d+|\btrue\b|\bfalse\b)"#,
        &[CWE::CWE89],
        &[CWE::CWE285],
        &[66],
    ),
    // Always-true/false shortcuts — simpler tautology forms (OR 1, AND 0).
    PatternEntry::new(
        r#"(?i)[\d)'"]\s+\b(?:OR|AND)\s+\d+\s*(?:[=<>!]|--|$|\))"#,
        &[CWE::CWE89],
        &[CWE::CWE285],
        &[66],
    ),
    // DDL injection — schema destruction or modification (DROP, CREATE, ALTER, TRUNCATE).
    PatternEntry::new(
        r"(?i)\b(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|INDEX|VIEW|TRIGGER|SCHEMA|DATABASE|SEQUENCE|PROCEDURE|FUNCTION|ROLE|USER)\b",
        &[CWE::CWE89],
        &[CWE::CWE400, CWE::CWE471],
        &[66],
    ),
    // DML injection — data tampering (DELETE, INSERT, UPDATE, REPLACE, MERGE).
    PatternEntry::new(
        r#"(?i)\b(?:DELETE\s+FROM|INSERT\s+INTO|UPDATE\s+[\w`"'\[]+[\w`"'\]]*\s+SET|REPLACE\s+INTO|MERGE\s+INTO)\b"#,
        &[CWE::CWE89],
        &[CWE::CWE471],
        &[66],
    ),
    // Stored-procedure / UDF execution — EXEC/EXECUTE/CALL with underscore names.
    // CWE-77: these calls can invoke OS-level procedures (e.g. xp_cmdshell).
    PatternEntry::new(
        r"(?i)\b(?:EXEC|EXECUTE)\s+\w*_\w+\s*\(|\bCALL\s+\w*_\w+\s*\(",
        &[CWE::CWE89, CWE::CWE77],
        &[CWE::CWE285],
        &[470],
    ),
    // Privilege manipulation — GRANT/REVOKE alter SQL-layer access controls.
    PatternEntry::new(
        r"(?i)\b(?:GRANT|REVOKE)\b",
        &[CWE::CWE89],
        &[CWE::CWE269],
        &[66],
    ),
    // Hex/binary literals — obfuscate string payloads to evade string-based filters.
    // CWE-116: improper encoding used as an evasion mechanism.
    PatternEntry::new(
        r"(?i)\b0x[0-9a-f]+\b|[Xx]'(?:[0-9a-fA-F]{2})+'",
        &[CWE::CWE89, CWE::CWE116],
        &[CWE::CWE285],
        &[66],
    ),
    // Percent-encoded metacharacters — URL-encode quotes, semicolons, and null bytes.
    // CWE-116: encoding evasion; null byte (%00) can terminate strings in some drivers.
    PatternEntry::new(
        r"(?i)%(27|22|3[bB]|2[dD]|23|2[fF]|00)|\x00",
        &[CWE::CWE89, CWE::CWE116],
        &[CWE::CWE285],
        &[66],
    ),
    // Information schema probing — enumerates tables, columns, and constraints.
    PatternEntry::new(
        r"(?i)\binformation_schema\b",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // Subquery injection — scalar or correlated subselects extract data row by row.
    PatternEntry::new(r"(?i)\(\s*select\s+", &[CWE::CWE89], &[CWE::CWE200], &[7]),
    // Blind time-delay attacks — SLEEP/WAITFOR/BENCHMARK cause measurable delays
    // used to exfiltrate data one bit at a time via timing side-channel.
    PatternEntry::new(
        r"(?i)\b(?:sleep|pg_sleep|waitfor[\s\t]+delay|benchmark)\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE208, CWE::CWE400],
        &[7],
    ),
    // CASE-based blind injection — conditional branching leaks data through query behaviour.
    PatternEntry::new(
        r"(?i)\bcase\s+when\s+.+?\s+then\b",
        &[CWE::CWE89],
        &[CWE::CWE208],
        &[7],
    ),
];

/// SQLite-specific injection patterns.
pub const SQLITE: &[PatternEntry] = &[
    // Internal schema tables — sqlite_master/schema reveal table DDL and structure.
    PatternEntry::new(
        r"(?i)\bsqlite_(?:master|temp_master|schema|temp_schema)\b",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // File I/O built-ins — load_extension mounts native libraries; writefile/readfile
    // perform arbitrary filesystem access outside the database sphere.
    // CWE-114: loading uncontrolled native code (load_extension).
    // CWE-610: referencing external file-system resources.
    PatternEntry::new(
        r"(?i)\b(?:load_extension|writefile|readfile)\s*\(",
        &[CWE::CWE89, CWE::CWE610, CWE::CWE114],
        &[CWE::CWE200, CWE::CWE285],
        &[470],
    ),
    // Encoding and fingerprinting built-ins — char()/hex() obfuscate injected strings;
    // randomblob()/sqlite_version() probe engine internals for targeted exploitation.
    PatternEntry::new(
        r"(?i)\b(?:randomblob|sqlite_version|char|hex)\s*\(",
        &[CWE::CWE89, CWE::CWE116],
        &[CWE::CWE497],
        &[54],
    ),
    // Database administration — ATTACH mounts arbitrary DB files; PRAGMA exposes
    // or alters engine settings; DETACH removes attached databases.
    PatternEntry::new(
        r"(?i)\bATTACH\b\s+DATABASE\b|\bDETACH\b\s+\w+|\bPRAGMA\b\s+\w+",
        &[CWE::CWE89],
        &[CWE::CWE200, CWE::CWE285],
        &[66],
    ),
    // Temporary table/view/trigger creation — used to stage data for exfiltration.
    PatternEntry::new(
        r"(?i)\bcreate\s+te?mp(?:orary)?\s+(?:table|view|trigger)\b",
        &[CWE::CWE89],
        &[CWE::CWE200],
        &[66],
    ),
    // Virtual table abuse — fts5/rtree virtual tables can expose memory or file content.
    PatternEntry::new(
        r"(?i)\bcreate\s+virtual\s+table\b",
        &[CWE::CWE89],
        &[CWE::CWE200],
        &[66],
    ),
    // Compile-option fingerprinting — reveals build-time feature flags used to
    // tailor follow-up exploits to the specific SQLite build.
    PatternEntry::new(
        r"(?i)\bsqlite_compileoption_(?:get|used)\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // GLOB pattern injection — used for pattern-based blind column enumeration.
    PatternEntry::new(r"(?i)\bglob\s*\(", &[CWE::CWE89], &[CWE::CWE200], &[7]),
    // zeroblob abuse — allocates large zero-filled blobs; can trigger OOM/DoS.
    PatternEntry::new(r"(?i)\bzeroblob\s*\(", &[CWE::CWE89], &[CWE::CWE400], &[66]),
    // Recursive CTE — WITH RECURSIVE enables complex blind extraction and row flooding.
    PatternEntry::new(
        r"(?i)\bwith\s+recursive\b",
        &[CWE::CWE89],
        &[CWE::CWE208, CWE::CWE400],
        &[7],
    ),
];

/// PostgreSQL-specific injection patterns.
pub const POSTGRES: &[PatternEntry] = &[
    // System catalog probing — pg_catalog, pg_tables, pg_class, etc. enumerate
    // schema, roles, settings, and statistics.
    PatternEntry::new(
        r"(?i)\bpg_catalog\b|\bpg_(?:tables|class|namespace|attribute|proc|user|roles|settings|indexes|stat_\w+)\b",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // Filesystem access functions — pg_read_file, pg_ls_dir, pg_write_file, etc.
    // read or list arbitrary server-side files as the database superuser.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\bpg_(?:read_file|read_binary_file|ls_dir|stat_file|write_file)\s*\(",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // Large object functions — lo_import/lo_export read and write arbitrary files
    // via the server-side large-object storage mechanism.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\blo_(?:import|export|get|put|unlink|open|read|write|lseek|close|creat|create|truncate)\s*\(",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // COPY TO/FROM FILE or PROGRAM — writes query output to disk or pipes it
    // through an OS command, enabling full arbitrary command execution.
    // CWE-78: OS command injection via COPY FROM PROGRAM.
    // CWE-610: arbitrary file read/write via COPY TO/FROM path.
    PatternEntry::new(
        r"(?i)\bcopy\b[\s\S]{0,200}\b(?:to|from)\b\s*(?:'[^']*'|program\b)",
        &[CWE::CWE89, CWE::CWE610, CWE::CWE78],
        &[CWE::CWE200, CWE::CWE285],
        &[470],
    ),
    // dblink cross-server execution — executes SQL on a remote PostgreSQL server,
    // effectively treating the DB as a pivot point for lateral movement.
    // CWE-77: command injection at the inter-server boundary.
    PatternEntry::new(
        r"(?i)\bdblink(?:_exec|_connect|_disconnect|_open|_fetch|_close|_get_connections|_cancel_query|_error_message)?\s*\(",
        &[CWE::CWE89, CWE::CWE77],
        &[CWE::CWE285],
        &[470],
    ),
    // Dollar-quoting evasion — $$ or $tag$ quoting bypasses single-quote filters
    // and is also used to embed anonymous code blocks.
    // CWE-184: the filter being bypassed does not account for this quoting form.
    PatternEntry::new(
        r"\$[^$]*\$",
        &[CWE::CWE89, CWE::CWE184],
        &[CWE::CWE285],
        &[66],
    ),
    // Anonymous DO blocks — execute arbitrary PL/pgSQL without creating a stored proc.
    // CWE-94: injects and immediately evaluates procedural code.
    PatternEntry::new(
        r"(?i)\bdo\s+(?:\$[^$]*\$|')",
        &[CWE::CWE89, CWE::CWE94],
        &[CWE::CWE285],
        &[470],
    ),
    // Extension loading — CREATE EXTENSION can load plpython3u, plperlu, or other
    // untrusted language handlers that enable arbitrary OS-level code execution.
    // CWE-114: process control via loading an uncontrolled native library.
    PatternEntry::new(
        r"(?i)\bcreate\s+extension\b",
        &[CWE::CWE89, CWE::CWE94, CWE::CWE114],
        &[CWE::CWE285],
        &[470],
    ),
    // Server configuration — ALTER SYSTEM SET writes to postgresql.conf,
    // persisting changes that survive server restarts.
    PatternEntry::new(
        r"(?i)\balter\s+system\s+set\b",
        &[CWE::CWE89],
        &[CWE::CWE285],
        &[66],
    ),
    // Cast operator abuse — PostgreSQL-specific :: syntax coerces types to bypass
    // input validation or WAF rules that inspect raw string content.
    // CWE-184: the blocklist does not account for the cast syntax form.
    PatternEntry::new(
        r"::\s*\w+",
        &[CWE::CWE89, CWE::CWE184],
        &[CWE::CWE285],
        &[66],
    ),
    // Server-side disruption functions — pg_sleep causes timing side-channels;
    // pg_terminate_backend/pg_cancel_backend disrupt active connections.
    PatternEntry::new(
        r"(?i)\bpg_(?:sleep|cancel_backend|terminate_backend|reload_conf|rotate_logfile)\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE400, CWE::CWE208],
        &[7],
    ),
    // System info fingerprinting — version(), current_database(), inet_server_addr(),
    // etc. leak server internals used to tailor follow-up exploits.
    PatternEntry::new(
        r"(?i)\b(?:version|current_database|current_schema|inet_server_addr|inet_server_port|pg_postmaster_start_time|pg_conf_load_time)\s*\(\s*\)",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // generate_series abuse — floods result sets or creates high-cardinality timing
    // loops used in blind injection side-channels.
    PatternEntry::new(
        r"(?i)\bgenerate_series\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE400, CWE::CWE208],
        &[7],
    ),
    // Format string injection — format('%s', user_input) builds dynamic SQL,
    // allowing an attacker to inject arbitrary query fragments at eval time.
    // CWE-95: user-controlled format string drives evaluated code generation.
    PatternEntry::new(
        r"(?i)\bformat\s*\(\s*'[^']*%[^']*'",
        &[CWE::CWE89, CWE::CWE95],
        &[CWE::CWE285],
        &[66],
    ),
    // RETURNING clause — extracts rows from INSERT/UPDATE/DELETE, turning
    // write-only statements into data-disclosure channels.
    PatternEntry::new(
        r"(?i)\breturning\s+[\w\*]",
        &[CWE::CWE89],
        &[CWE::CWE200],
        &[66],
    ),
    // Role/session elevation — SET ROLE and SET SESSION AUTHORIZATION switch
    // the injected session to a higher-privilege identity.
    PatternEntry::new(
        r"(?i)\bset\s+(?:role|session\s+authorization)\b",
        &[CWE::CWE89],
        &[CWE::CWE269],
        &[66],
    ),
];

/// DuckDB-specific injection patterns.
pub const DUCKDB: &[PatternEntry] = &[
    // System table functions — duckdb_tables(), duckdb_columns(), etc. enumerate
    // schema, types, extensions, and engine settings.
    PatternEntry::new(
        r"(?i)\bduckdb_(?:tables|columns|schemas|databases|types|functions|settings|extensions|views|indexes|sequences|constraints|keywords|optimizers)\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // File read functions — read_csv/parquet/json/text/blob load arbitrary local files
    // into query results, leaking server-side file content.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\bread_(?:csv|csv_auto|parquet|json|json_auto|text|blob)\s*\(",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // COPY TO file — writes query output to an arbitrary server-side path.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\bcopy\b[\s\S]{0,200}\bto\b\s*'[^']*'",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // EXPORT DATABASE — dumps the entire database to an external directory.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\bexport\s+database\b",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // ATTACH external database — mounts an arbitrary .db file as a queryable catalog,
    // exposing its contents or enabling writes to unintended databases.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\battach\b\s*(?:database\b\s*)?'[^']*'",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[66],
    ),
    // Remote file access via httpfs — read_*(′https://…′/′s3://…′) fetches data from
    // attacker-controlled or internal network endpoints (SSRF-class impact).
    // CWE-610: externally controlled reference to a remote resource.
    PatternEntry::new(
        r"(?i)\bread_\w+\s*\(\s*'(?:https?|s3|gcs|az)://",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[664],
    ),
    // Glob file enumeration — glob(′path/*′) lists server-side filesystem entries,
    // enabling directory traversal reconnaissance.
    // CWE-610: externally controlled reference to a filesystem resource.
    PatternEntry::new(
        r"(?i)\bglob\s*\(\s*'[^']*'",
        &[CWE::CWE89, CWE::CWE610],
        &[CWE::CWE200],
        &[54],
    ),
    // CREATE SECRET — injects cloud-provider credential definitions (AWS, GCS, Azure)
    // that subsequent queries will use, enabling credential hijacking.
    PatternEntry::new(
        r"(?i)\bcreate\s+(?:or\s+replace\s+)?secret\b",
        &[CWE::CWE89],
        &[CWE::CWE200, CWE::CWE285],
        &[66],
    ),
    // duckdb_secrets() — reads stored cloud credentials from the secrets manager,
    // directly exposing API keys and access tokens.
    PatternEntry::new(
        r"(?i)\bduckdb_secrets\s*\(",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // Extension load/install — LOAD or INSTALL executes native extension code,
    // equivalent to loading an arbitrary shared library into the DB process.
    // CWE-114: process control via uncontrolled native library loading.
    PatternEntry::new(
        r"(?i)\b(?:load|install)\s+'[^']*'",
        &[CWE::CWE89, CWE::CWE94, CWE::CWE114],
        &[CWE::CWE285],
        &[470],
    ),
    // Macro/function injection — CREATE MACRO or CREATE FUNCTION defines new
    // executable logic inside the database that persists beyond the injection.
    // CWE-94: injects and registers arbitrary code as a database object.
    PatternEntry::new(
        r"(?i)\bcreate\s+(?:or\s+replace\s+)?(?:macro|function)\b",
        &[CWE::CWE89, CWE::CWE94],
        &[CWE::CWE285],
        &[470],
    ),
    // SUMMARIZE/DESCRIBE probing — returns column names, types, and statistics,
    // leaking schema details without querying information_schema directly.
    PatternEntry::new(
        r"(?i)\b(?:summarize|describe)\s+\w+",
        &[CWE::CWE89],
        &[CWE::CWE497],
        &[54],
    ),
    // Recursive CTE — WITH RECURSIVE enables complex blind extraction loops
    // and can create high-cardinality row sets for timing side-channels.
    PatternEntry::new(
        r"(?i)\bwith\s+recursive\b",
        &[CWE::CWE89],
        &[CWE::CWE208, CWE::CWE400],
        &[7],
    ),
];
