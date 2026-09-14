# We Built a Deliberately Vulnerable COBOL Banking App — Here's What We Learned

*Posted by the Pixee engineering team*

---

COBOL processes an estimated $3 trillion in financial transactions every day.
It runs 95% of ATM transactions in the United States. It handles roughly 80%
of in-person credit card transactions globally. The IRS runs on it. Medicare
runs on it. Most major banks run on it. The code doing this work is, on average,
somewhere between 30 and 60 years old — written by programmers who are mostly
retired or dead, maintained by teams who have often never seen a mainframe.

And yet if you search for "intentionally vulnerable COBOL application," you get
almost nothing.

DVWA (Damn Vulnerable Web App) exists for PHP. WebGoat exists for Java. Juice
Shop exists for Node. There are SQL injection sandboxes, XSS playgrounds, and
CTF challenges in every language a bootcamp graduate has ever touched. COBOL
— which underpins more of the global economy than all of those combined — has
essentially zero dedicated security training tooling.

So we built some.

---

## Why Pixee Needs This

Pixee builds automated code remediation tools. When a static analyzer finds a
vulnerability, Pixee generates and applies the fix — a real code change, not
just a ticket. We support multiple languages, and earlier this year we started
seriously investing in COBOL support.

The problem with building automated remediation for any language is that you
need concrete examples of the vulnerability class you're fixing, end-to-end.
Not a description. Not a CVE. An actual running system where you can trigger
the bug, see the impact, apply a fix, and verify it's gone.

For Java, we have WebGoat. For PHP, we have DVWA. For COBOL? We had nothing.
So we built COBOLBank: a fake banking portal, running real GnuCOBOL, with
every classic web vulnerability implemented in authentic COBOL patterns.

---

## Attempt One: Wrap COBOL in Node.js

The first version took the obvious route. We built a Node.js/Express API server
that invoked COBOL binaries as child processes. The frontend called the API.
The API shelled out to a COBOL binary with environment variables. The binary
ran and wrote output to a file or stdout. Node collected it and sent the
response.

It technically worked. The COBOL programs ran. We had users, accounts, and a
SQLite database. But when we sat down to write the SQL injection challenge,
something felt wrong.

The SQL injection was in JavaScript:

```javascript
// Node.js
const query = `SELECT * FROM users WHERE username='${username}'`;
```

The COBOL was just executing whatever query the JavaScript gave it. The attack
surface — the thing a security researcher was actually poking at — was Express.
If we fixed the injection in the COBOL but not in the Node layer, nothing
changed. The "COBOL vulnerability" was a lie. We were just building a JavaScript
vulnerable app that happened to have COBOL running somewhere in the back.

Not good enough.

---

## Going Full COBOL CGI

The realization came from thinking about history. Apache has had `mod_cgi` since
the mid-1990s. CGI — the Common Gateway Interface — is literally how COBOL was
first connected to web servers in the mainframe-adjacent systems of that era.
A web request arrives, Apache forks a process, the process reads CGI environment
variables and writes HTTP headers + body to stdout, Apache relays it. That's
the whole protocol.

We ripped out Node.js entirely.

The new architecture: Apache receives every request, rewrites `/api/*` to
`/cgi-bin/*`, forks a GnuCOBOL binary, and relays its stdout as the HTTP
response. No Node. No Python. No intermediary of any kind. If you hit
`POST /api/auth/login`, you're talking directly to a compiled COBOL binary.
The SQL injection is in COBOL. The path traversal is in COBOL. The command
injection is in COBOL.

The Dockerfile reflects this clearly — the builder stage has GnuCOBOL and GCC,
the runtime stage has Apache and `libcob4`. That's it. `node` is not installed
anywhere.

```dockerfile
FROM debian:bookworm-slim AS builder
RUN apt-get install -y gnucobol gcc make libsqlite3-dev pkg-config

FROM debian:bookworm-slim
RUN apt-get install -y apache2 libcob4 libsqlite3-0 sqlite3
RUN a2enmod cgi rewrite headers
```

---

## The COPY Book Architecture

Eleven CGI programs means eleven programs that all need to read the same CGI
environment variables, write the same HTTP headers, and speak the same JSON
conventions. COBOL has a mechanism for this: COPY books. They're roughly
analogous to C header files or Java interfaces — a shared source file that gets
textually included wherever needed.

We wrote five:

- `ws-cgi.cpy` — WORKING-STORAGE definitions for every CGI variable the
  programs need: `REQUEST_METHOD`, `QUERY_STRING`, `HTTP_COOKIE`, `PATH_INFO`,
  plus their 88-level condition names:

```cobol
       01 CGI-VARS.
          05 CGI-REQUEST-METHOD   PIC X(8).
             88 CGI-IS-GET        VALUE "GET".
             88 CGI-IS-POST       VALUE "POST".
          05 CGI-QUERY-STRING     PIC X(4096).
          05 CGI-HTTP-COOKIE      PIC X(4096).
```

- `proc-cgi.cpy` — Paragraphs for reading those variables and calling the C
  bridge functions: `READ-CGI-VARS`, `READ-POST-BODY`, `GET-QUERY-PARAM`,
  `GET-JSON-FIELD`

- `ws-http.cpy` and `proc-http.cpy` — HTTP response fields and the
  `WRITE-JSON-HEADER` / `WRITE-JSON-ERROR` paragraphs

- `ws-sql.cpy` — The query and result buffer fields used by every program that
  calls SQLite

Each CGI program then opens with three COPY statements in WORKING-STORAGE and
gets all of this infrastructure for free. Feels very 1985, works exactly as
intended.

---

## The C Bridge Problem

COBOL cannot talk to SQLite natively. GnuCOBOL can, however, call C functions.
We wrote a thin C file — `cobol-sqlite.c` — with three functions:

- `sqlexec(query, result)` — executes a SQL query against the SQLite database,
  returns the rows as a JSON string
- `jsonget(json, fieldname, value)` — extracts a field value from a JSON string
- `urlparam(querystring, paramname, value)` — URL-decodes a named parameter
  from a query string

COBOL PIC X(N) fields are fixed-length and space-padded, not null-terminated.
The C functions receive a pointer to the raw COBOL field memory, strip trailing
spaces to get the actual string, do their work, and write back into the output
field space-padded to its declared length. It's an unusual calling convention
but it works cleanly.

The COBOL side looks like this:

```cobol
       CALL "sqlexec" USING BY REFERENCE WS-SQL-QUERY
                            BY REFERENCE WS-SQL-RESULT
```

GnuCOBOL resolves `CALL "sqlexec"` at runtime by looking in `COB_LIBRARY_PATH`
for a file named `sqlexec.so`, loading it with `dlopen`, and finding the symbol
`sqlexec` with `dlsym`. We compile the C file as a shared library, copy it
three times under the three names the COBOL programs call, and set
`COB_LIBRARY_PATH=/app/cobol/lib` in the Apache environment.

This approach — building a thin C shim for anything COBOL can't do natively,
loaded via `COB_LIBRARY_PATH` — is how real GnuCOBOL programs talk to external
libraries. We were following the established pattern.

---

## The Hyphen Problem

We initially named our C functions in COBOL style: `sql-exec`, `json-get`,
`url-param`. Hyphens are idiomatic in COBOL identifiers. COBOL data names,
paragraph names, program names — they all use hyphens. It seemed natural.

The COBOL programs called `CALL "sql-exec"`. GnuCOBOL found `sql-exec.so` in
`COB_LIBRARY_PATH` with no trouble. Then it called `dlsym(handle, "sql-exec")`.

```
libcob: error: module 'url-param' not found
```

An hour of staring at this. The `.so` file was right there. The `COB_LIBRARY_PATH`
was set. The file was readable. Why couldn't GnuCOBOL find it?

The answer: `dlsym` is looking for a C symbol named `url-param`. And `url-param`
is not a valid C identifier. The hyphen is the subtraction operator. `url-param`
means `url` minus `param` to the C linker. There is no symbol named `url-param`
in any shared library — the C compiler would never produce one.

COBOL uses hyphens everywhere. C uses underscores. When they meet at the `dlsym`
boundary, one of them has to give. We renamed everything: `sqlexec`, `jsonget`,
`urlparam`. Changed every `CALL` statement in every COBOL program, updated the
Makefile, renamed the `.so` targets. Problem solved, lesson learned.

---

## The PROCEDURE DIVISION Fall-Through Bug

With the C bridge working, we rebuilt and ran a login test. Apache returned 500.

The error log:

```
[cgid:error] malformed header from script 'login': Bad header:
```

We ran the binary directly inside the container with the CGI environment
variables set:

```
Content-Type: application/json
Access-Control-Allow-Origin: *

{"error": ""}
Content-Type: application/json
Access-Control-Allow-Origin: *

{"success": false, "error": "Invalid credentials", ...}
```

Two sets of headers. A spurious `{"error": ""}` in the middle. The binary was
producing output twice.

This is a fundamental COBOL behavior that we'd structured ourselves directly
into. In COBOL, if a paragraph doesn't end with `STOP RUN` or `GO TO`, execution
falls through to the next paragraph. We'd put the COPY books at the top of the
PROCEDURE DIVISION:

```cobol
PROCEDURE DIVISION.
COPY "proc-http.cpy".   *> defines WRITE-JSON-HEADER first
COPY "proc-cgi.cpy".    *> defines READ-CGI-VARS next
MAIN-PARA.
    PERFORM READ-CGI-VARS
    ...
```

When the program started, execution began at the first paragraph encountered
— `WRITE-JSON-HEADER` from the copybook. It wrote the Content-Type header,
set `HTTP-HEADERS-WRITTEN` to "Y", and fell through to `WRITE-JSON-ERROR`.
`WRITE-JSON-ERROR` checked "are headers sent? No — wait, actually yes, the
flag is set" but still wrote `{"error": ""}` because the condition was wrong
at that point. Then it fell through to `READ-CGI-VARS`, then `MAIN-PARA`, which
ran properly and wrote everything again.

The fix was simple once we saw it: `MAIN-PARA` must be the **first** paragraph
in the PROCEDURE DIVISION. The COPY books go at the **end**, after all the
local paragraphs. COBOL starts executing at the first paragraph it encounters.
If `MAIN-PARA` is first and ends with `STOP RUN`, nothing falls through.

We wrote a fork agent to restructure all eleven programs simultaneously.

---

## The Blank Line That Wasn't

With the structural fix in place, the headers printed once. But Apache still
occasionally complained about malformed headers, and the response sometimes
looked wrong.

HTTP CGI requires a blank line between the header block and the response body.
We'd used `DISPLAY SPACE` to output it:

```cobol
WRITE-JSON-HEADER.
    DISPLAY "Content-Type: application/json"
    DISPLAY "Access-Control-Allow-Origin: *"
    DISPLAY SPACE    *> intended blank line separator
    MOVE "Y" TO HTTP-HEADERS-WRITTEN.
```

GnuCOBOL's `DISPLAY` statement always appends a newline. `DISPLAY SPACE` outputs
a single space character followed by a newline: `" \n"`. That's not a blank line
— it's a line containing a space. Apache reads it as a header with an empty
value, and then the next thing it sees is `{"success":...}` which also isn't
a valid header, so it gives up.

The fix: `DISPLAY x'0a' WITH NO ADVANCING`. The hex literal `x'0a'` is a
line-feed character. `WITH NO ADVANCING` suppresses `DISPLAY`'s own trailing
newline. So we output just `\n`. Combined with the `\n` that already ends the
`Access-Control-Allow-Origin` line, we get `\n\n` — the proper blank line that
HTTP requires.

```cobol
    DISPLAY "Access-Control-Allow-Origin: *"
    DISPLAY x'0a' WITH NO ADVANCING
```

Subtle. Annoying. Fixed.

---

## What We Ended Up With

Eleven COBOL CGI programs. Five shared COPY books. A C SQLite bridge that
compiles to three shared libraries. Apache mod_cgi serving them all. A
multi-stage Docker build that leaves no Node.js in the runtime image.

Every vulnerability lives in the COBOL, implemented in patterns that a COBOL
programmer from 1987 would immediately recognize:

```cobol
*> SQL injection: STRING concatenation into a query
BUILD-LOGIN-QUERY.
    STRING
        "SELECT id, username, role FROM users"
        " WHERE username='"
        FUNCTION TRIM(WS-USERNAME) DELIMITED SIZE
        "' AND password='"
        FUNCTION TRIM(WS-PASSWORD) DELIMITED SIZE
        "'"
        DELIMITED SIZE
        INTO WS-SQL-QUERY
    END-STRING.

*> Path traversal: ASSIGN TO DYNAMIC on user-controlled path
FILE-CONTROL.
    SELECT REPORT-FILE ASSIGN TO DYNAMIC WS-FULL-PATH
        ORGANIZATION IS LINE SEQUENTIAL.

*> Command injection: CALL "SYSTEM" with unsanitized input
RUN-REPORT-COMMAND.
    STRING "echo 'Report: "
        FUNCTION TRIM(WS-REPORT-TYPE) DELIMITED SIZE
        "' >> /tmp/cobol-goat/reports.log"
        DELIMITED SIZE INTO WS-SHELL-CMD
    END-STRING
    CALL "SYSTEM" USING WS-SHELL-CMD RETURNING WS-SYS-RESULT.
```

IDOR because nobody wrote an ownership check when they wrote the account lookup
in 1987. Hardcoded credentials because `01 WS-ADMIN-PASS PIC X(16) VALUE "c0b0ladm1n"` was how you configured a system before environment variables were
common. Numeric overflow because `PIC 9(8)V99` has a hard upper bound of
$99,999,999.99 and nobody thought to validate the input.

These aren't contrived. These are patterns we see in production COBOL codebases
today.

---

## Why Pixee Supports COBOL

Automated code remediation for COBOL is genuinely hard, in ways that don't apply
to modern languages.

There's no widely-used, high-quality AST library for COBOL. The language has
dozens of dialects — IBM Enterprise COBOL, Micro Focus, GnuCOBOL, and legacy
variants all differ in meaningful ways. COBOL code is frequently 40-60 years
old with no test suite, which means a remediation tool cannot run tests to
verify its changes compile cleanly and produce correct results. The language
itself has evolved but its installed base hasn't — most production COBOL hasn't
been touched in years.

But the vulnerabilities are real. SQL injection in COBOL looks different than
SQL injection in Python — the query is assembled with `STRING ... DELIMITED SIZE
INTO WS-QUERY` instead of f-strings — but it's the same underlying problem, and
it's in code that processes real transactions at real banks. Command injection
through `CALL "SYSTEM"` is not a theoretical risk; it's how COBOL programs have
always invoked external utilities, and there's forty years of legacy code doing
it without sanitization.

Pixee's approach is to meet the code where it lives. We detect the patterns that
create vulnerabilities — `STRING` concatenation into SQL field names, unsanitized
paths in `ASSIGN TO DYNAMIC` clauses, `CALL "SYSTEM"` with user-controlled
input — and produce safe, compilable fixes that a COBOL programmer recognizes as
idiomatic. Not a rewrite. A minimal change, in the same style as the surrounding
code, that closes the vulnerability.

COBOLBank gives us and our users a way to see that end-to-end: here is the
vulnerable COBOL, here is how to trigger it, here is the fix Pixee generates,
here is the patched program running correctly.

---

## COBOL Security Is Unglamorous and Critical

The security research community doesn't spend much time on COBOL. It's not
fashionable. There are no COBOL tracks at DEF CON. The mainframe hacking
community is small and specialized, and most of their work is about RACF and
JES2 and VTAM — the infrastructure layer — rather than the application code
running on top of it.

But the application code is where the financial logic lives. The business rules
that govern whether a transaction clears, whether an account has sufficient
funds, whether a wire transfer is authorized — all of that is in COBOL. And
most of it has never been security-reviewed by anyone who knows what SQL
injection is, because most of it was written before SQL injection was a named
concept.

The people who wrote that code are largely gone. The people who maintain it are
specialists in an increasingly rare skill, focused on keeping the system running,
not on what happens when someone sends `' OR '1'='1` to the login field.
Security tooling that works for them needs to understand COBOL — not as a
curiosity or an afterthought, but as a first-class target.

That's what we're building at Pixee. COBOLBank is how we make it concrete.

---

## Try It Yourself

```bash
git clone https://github.com/pixee/cobol-goat.git
cd cobol-goat
docker compose up
```

Open http://localhost:3000. Log in as `admin` / `c0b0ladm1n`. See what breaks.

The COBOL source is in `cobol/cgi/`. The shared definitions are in
`cobol/copybooks/`. The C SQLite bridge is `cobol/lib/cobol-sqlite.c`. It's all
readable, buildable, and deliberately broken.

If you're working on COBOL security tooling, security training for financial
institutions, or just curious what forty years of financial infrastructure
actually looks like — we'd love to hear from you. Reach us at
[pixee.ai](https://pixee.ai).
