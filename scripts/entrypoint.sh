#!/bin/bash
set -e

DB_PATH="${COBOLGOAT_DB:-/app/database/cobolgoat.db}"
LOG_DIR=/tmp/cobol-goat

mkdir -p "$LOG_DIR/sessions"
chmod -R 777 "$LOG_DIR"

# ── Seed database ────────────────────────────────────────────────────────────
echo "[COBOLBank] Initialising database at $DB_PATH"

sqlite3 "$DB_PATH" <<'SQL'
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role     TEXT,
    email    TEXT
);

CREATE TABLE IF NOT EXISTS accounts (
    id      INTEGER PRIMARY KEY,
    owner   TEXT,
    balance REAL,
    ssn     TEXT
);

CREATE TABLE IF NOT EXISTS secret_data (
    id    INTEGER PRIMARY KEY,
    key   TEXT,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    userId    TEXT,
    action    TEXT,
    details   TEXT
);

-- VULNERABILITY: plaintext passwords
INSERT OR IGNORE INTO users VALUES (1, 'admin',   'c0b0ladm1n',  'admin', 'admin@cobolbank.local');
INSERT OR IGNORE INTO users VALUES (2, 'alice',   'password123', 'user',  'alice@cobolbank.local');
INSERT OR IGNORE INTO users VALUES (3, 'bob',     'letmein',     'user',  'bob@cobolbank.local');
INSERT OR IGNORE INTO users VALUES (4, 'charlie', 'qwerty',      'user',  'charlie@cobolbank.local');

-- VULNERABILITY: SSNs stored in plaintext, no encryption
INSERT OR IGNORE INTO accounts VALUES (1001, 'alice',   15432.50,  '123-45-6789');
INSERT OR IGNORE INTO accounts VALUES (1002, 'bob',      2100.00,  '987-65-4321');
INSERT OR IGNORE INTO accounts VALUES (1003, 'admin',  999999.99,  '000-00-0000');
INSERT OR IGNORE INTO accounts VALUES (1004, 'charlie',   500.00,  '555-12-9876');

-- VULNERABILITY: sensitive keys stored in database
INSERT OR IGNORE INTO secret_data VALUES (1, 'aws_master_key',  'AKIAIOSFODNN7EXAMPLE');
INSERT OR IGNORE INTO secret_data VALUES (2, 'stripe_secret',   'sk_live_TRAINING_EXAMPLE_51abc123xyz');
INSERT OR IGNORE INTO secret_data VALUES (3, 'encryption_key',  'AES256KEY1234567ABCDEFGHIJKLMNOP');
SQL

echo "[COBOLBank] Database ready."

# ── Seed log files with fake history ─────────────────────────────────────────
# VULNERABILITY: logs contain plaintext passwords
cat >> "$LOG_DIR/auth.log" <<'LOG'
[AUTH] user=alice pass=password123
[AUTH] user=admin pass=c0b0ladm1n
[AUTH] user=bob pass=letmein
[AUTH] user=admin pass=c0b0ladm1n
LOG

cat >> "$LOG_DIR/sql.log" <<'LOG'
[SQL] SELECT id, username, role FROM users WHERE username='alice' AND password='password123'
[SQL] SELECT id, username, role FROM users WHERE username='admin' AND password='c0b0ladm1n'
LOG

# ── Seed session files (VULNERABILITY: predictable sequential tokens) ─────────
echo "USERNAME=admin" > "$LOG_DIR/sessions/1000.dat"
echo "ROLE=admin"    >> "$LOG_DIR/sessions/1000.dat"

echo "USERNAME=alice" > "$LOG_DIR/sessions/1001.dat"
echo "ROLE=user"     >> "$LOG_DIR/sessions/1001.dat"

chmod 644 "$LOG_DIR/sessions"/*.dat

echo "[COBOLBank] Starting Apache..."
# Forward Apache logs to stdout/stderr so docker logs works
ln -sf /dev/stdout /tmp/cobol-goat/apache-access.log 2>/dev/null || true
ln -sf /dev/stderr /tmp/cobol-goat/apache-error.log  2>/dev/null || true

exec apache2ctl -D FOREGROUND
