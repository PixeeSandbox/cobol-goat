'use strict';

// COBOLGoat - Intentionally Vulnerable COBOL Training Application
// WARNING: This server contains intentional security vulnerabilities for educational purposes.
// DO NOT deploy in production.

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cors = require('cors');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

let db;
function initDatabase() {
  const Database = require('better-sqlite3');

  const primaryPath = '/app/database/cobolgoat.db';
  const fallbackPath = '/tmp/cobol-goat/cobolgoat.db';

  let dbPath;
  try {
    fs.mkdirSync(path.dirname(primaryPath), { recursive: true });
    dbPath = primaryPath;
  } catch {
    fs.mkdirSync(path.dirname(fallbackPath), { recursive: true });
    dbPath = fallbackPath;
  }

  console.log(`[DB] Opening database at ${dbPath}`);
  db = new Database(dbPath);

  // VULNERABILITY: passwords stored in plaintext
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id       INTEGER PRIMARY KEY,
      username TEXT,
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

    CREATE TABLE IF NOT EXISTS products (
      id          INTEGER PRIMARY KEY,
      name        TEXT,
      price       REAL,
      description TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id        INTEGER PRIMARY KEY,
      timestamp TEXT,
      userId    TEXT,
      action    TEXT,
      details   TEXT
    );
  `);

  // Seed users (plaintext passwords — intentional vulnerability)
  const seedUsers = [
    [1, 'admin',   'c0b0ladm1n',  'admin', 'admin@cobolgoat.local'],
    [2, 'alice',   'password123', 'user',  'alice@cobolgoat.local'],
    [3, 'bob',     'letmein',     'user',  'bob@cobolgoat.local'],
    [4, 'charlie', 'qwerty',      'user',  'charlie@cobolgoat.local'],
  ];
  const insertUser = db.prepare(
    'INSERT OR IGNORE INTO users (id, username, password, role, email) VALUES (?, ?, ?, ?, ?)'
  );
  for (const u of seedUsers) insertUser.run(...u);

  // Seed accounts (SSNs exposed — intentional vulnerability)
  const seedAccounts = [
    [1001, 'Alice', 15432.50, '123-45-6789'],
    [1002, 'Bob',    2100.00, '987-65-4321'],
    [1003, 'admin', 999999.99,'000-00-0000'],
  ];
  const insertAccount = db.prepare(
    'INSERT OR IGNORE INTO accounts (id, owner, balance, ssn) VALUES (?, ?, ?, ?)'
  );
  for (const a of seedAccounts) insertAccount.run(...a);

  // Seed products
  const seedProducts = [
    [1, 'COBOL Manual',          49.99, 'The definitive COBOL programming reference.'],
    [2, 'Mainframe Guide',       89.99, 'A complete guide to mainframe computing.'],
    [3, 'Legacy System Handbook',34.99, 'Maintain and extend legacy systems with confidence.'],
    [4, 'VSAM Reference',        69.99, 'Virtual Storage Access Method in depth.'],
    [5, 'JCL Cookbook',          44.99, 'Job Control Language recipes for every occasion.'],
  ];
  const insertProduct = db.prepare(
    'INSERT OR IGNORE INTO products (id, name, price, description) VALUES (?, ?, ?, ?)'
  );
  for (const p of seedProducts) insertProduct.run(...p);

  console.log('[DB] Database initialized and seeded.');
}

// ---------------------------------------------------------------------------
// COBOL calling helper
// ---------------------------------------------------------------------------

// VULNERABILITY: verbose errors expose stack traces to callers
function callCobol(program, ...args) {
  // Prefer /app installation; fall back to local dev path
  const appBin  = `/app/cobol/bin/${program}`;
  const localBin = `./cobol/bin/${program}`;
  const binPath  = fs.existsSync(appBin) ? appBin : localBin;

  // Build command — arguments are NOT sanitised (intentional for command-injection challenges)
  const quotedArgs = args.map(a => `"${a}"`).join(' ');
  const cmd = `${binPath} ${quotedArgs}`;

  try {
    // VULNERABILITY: verbose errors — capture both stdout and stderr always
    const stdout = execSync(cmd, { timeout: 5000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
    try {
      return JSON.parse(stdout.trim());
    } catch {
      return { raw: stdout.trim() };
    }
  } catch (err) {
    // Non-zero exit: COBOL program may have written valid JSON to stdout even on failure
    // (e.g. login failure still returns the SQL query for the injection challenge)
    const stdout = err.stdout ? err.stdout.toString().trim() : '';
    if (stdout) {
      try {
        return JSON.parse(stdout);
      } catch {
        return { raw: stdout };
      }
    }
    // VULNERABILITY: return full stderr + stack trace on complete failure
    return {
      error:   err.stderr ? err.stderr.toString() : err.message,
      details: err.stack,
    };
  }
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// VULNERABILITY: CORS open to all origins
app.use(cors({ origin: true, credentials: true }));

// VULNERABILITY: X-Powered-By left on (default Express behaviour)
// (helmet is intentionally omitted)

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABILITY: hardcoded weak session secret, no secure/httpOnly flags
app.use(session({
  secret: 'cobol-goat-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,   // works over plain HTTP — intentional
    httpOnly: false, // JS can read the cookie — intentional
  },
}));

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------

// POST /api/auth/login
// VULNERABILITY: SQL query built by COBOL is returned to client (data exposure)
// VULNERABILITY: no rate limiting
app.post('/api/auth/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // Call COBOL login program — args not sanitised
  const cobolResult = callCobol('login', username, password);

  // VULNERABILITY: execute whatever SQL query COBOL produced, directly against SQLite
  let rows = [];
  if (cobolResult.query) {
    try {
      // String-concatenation query — intentional SQL injection surface
      rows = db.prepare(cobolResult.query).all();
    } catch (e) {
      rows = [{ sqlError: e.message }];
    }
  }

  if (rows.length > 0 && !cobolResult.error) {
    const user = rows[0];
    req.session.user = {
      userId:   user.id,
      username: user.username,
      role:     user.role,
    };
  }

  // VULNERABILITY: return full COBOL output including SQL query string
  res.json({ ...cobolResult, rows });
});

// POST /api/auth/logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ message: 'Logged out' }));
});

// GET /api/auth/status
app.get('/api/auth/status', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ---------------------------------------------------------------------------
// Account endpoints
// ---------------------------------------------------------------------------

// GET /api/accounts/:id
// VULNERABILITY: userId comes from query param, NOT from session (IDOR)
app.get('/api/accounts/:id', (req, res) => {
  const accountId = req.params.id;
  // VULNERABILITY: trusting user-supplied userId instead of req.session.user
  const userId = req.query.userId || (req.session.user && req.session.user.userId) || '0';

  const cobolResult = callCobol('account-lookup', accountId, userId);

  let rows = [];
  if (cobolResult.query) {
    try {
      rows = db.prepare(cobolResult.query).all();
    } catch (e) {
      rows = [{ sqlError: e.message }];
    }
  }

  res.json({ ...cobolResult, rows });
});

// ---------------------------------------------------------------------------
// Search endpoint
// ---------------------------------------------------------------------------

// GET /api/search?q=searchTerm
// VULNERABILITY: COBOL returns a SQL query string; it is executed verbatim (SQL injection)
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q || '';

  const cobolResult = callCobol('search', searchTerm);

  let rows = [];
  if (cobolResult.query) {
    try {
      // VULNERABILITY: user-controlled SQL string executed directly
      rows = db.prepare(cobolResult.query).all();
    } catch (e) {
      rows = [{ sqlError: e.message }];
    }
  }

  res.json({ ...cobolResult, rows });
});

// ---------------------------------------------------------------------------
// Transfer endpoint
// ---------------------------------------------------------------------------

// POST /api/transfer
// VULNERABILITY: no CSRF protection, no auth check on session ownership
app.post('/api/transfer', (req, res) => {
  const { fromAccount = '', toAccount = '', amount = '' } = req.body;
  const cobolResult = callCobol('transfer', fromAccount, toAccount, amount);
  res.json(cobolResult);
});

// ---------------------------------------------------------------------------
// File read endpoint
// ---------------------------------------------------------------------------

// GET /api/files/:filename
// VULNERABILITY: path traversal in both COBOL call and Node fs.readFileSync
app.get('/api/files/:filename', (req, res) => {
  const filename = req.params.filename;

  // VULNERABILITY: filename passed unsanitised to COBOL (path traversal / command injection)
  const cobolResult = callCobol('file-read', filename);

  // VULNERABILITY: path traversal — user controls the suffix after /app/reports/
  let fileContents = null;
  try {
    fileContents = fs.readFileSync('/app/reports/' + filename, 'utf8');
  } catch (e) {
    fileContents = { error: e.message };
  }

  res.json({ ...cobolResult, fileContents });
});

// ---------------------------------------------------------------------------
// Report generation endpoint
// ---------------------------------------------------------------------------

// POST /api/reports/generate
// VULNERABILITY: reportType and email are passed unsanitised to COBOL
app.post('/api/reports/generate', (req, res) => {
  const { reportType = '', email = '' } = req.body;
  const cobolResult = callCobol('report-gen', reportType, email);
  res.json(cobolResult);
});

// ---------------------------------------------------------------------------
// Admin endpoint
// ---------------------------------------------------------------------------

// GET /api/admin/action
// VULNERABILITY: role comes from query param, not from session (privilege escalation)
app.get('/api/admin/action', (req, res) => {
  const { userId = '', role = '', action = '' } = req.query;
  // VULNERABILITY: trusting user-supplied role instead of req.session.user.role
  const cobolResult = callCobol('admin-check', userId, role, action);
  res.json(cobolResult);
});

// ---------------------------------------------------------------------------
// Interest calculation endpoint
// ---------------------------------------------------------------------------

// POST /api/interest/calculate
app.post('/api/interest/calculate', (req, res) => {
  const { principal = '', rate = '', years = '' } = req.body;
  const cobolResult = callCobol('interest-calc', principal, rate, years);
  res.json(cobolResult);
});

// ---------------------------------------------------------------------------
// Config endpoint
// ---------------------------------------------------------------------------

// GET /api/config
// VULNERABILITY: no authentication check; exposes secrets
app.get('/api/config', (_req, res) => {
  const cobolResult = callCobol('config-reader');
  res.json(cobolResult);
});

// ---------------------------------------------------------------------------
// Debug endpoints
// ---------------------------------------------------------------------------

// GET /api/debug/env
// VULNERABILITY: exposes all process environment variables; no auth required
app.get('/api/debug/env', (_req, res) => {
  res.json(process.env);
});

// GET /api/debug/logs
// VULNERABILITY: exposes application log files; no auth required
app.get('/api/debug/logs', (_req, res) => {
  const logDir = '/tmp/cobol-goat';
  const logFiles = ['auth.log', 'application.log'];
  const logs = {};

  for (const file of logFiles) {
    const logPath = path.join(logDir, file);
    try {
      logs[file] = fs.readFileSync(logPath, 'utf8');
    } catch (e) {
      logs[file] = { error: e.message };
    }
  }

  res.json(logs);
});

// ---------------------------------------------------------------------------
// Global error handler
// VULNERABILITY: returns full stack trace to the client
// ---------------------------------------------------------------------------

// 404 — verbose path disclosure
app.use((req, res) => {
  res.status(404).json({
    error:   'Not Found',
    message: `Path not found: ${req.originalUrl}`,
    method:  req.method,
  });
});

// 500 — full stack trace in response
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    error:   err.message,
    stack:   err.stack,
    details: 'An unexpected error occurred. See stack trace above.',
  });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;

initDatabase();

app.listen(PORT, () => {
  console.log(`[COBOLGoat] Server running on http://localhost:${PORT}`);
  console.log('[COBOLGoat] WARNING: This server is intentionally vulnerable. Do not expose to the internet.');
});

module.exports = app;
