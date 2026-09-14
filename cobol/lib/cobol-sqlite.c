/*
 * COBOLBank - C SQLite bridge for GnuCOBOL CGI programs
 *
 * Functions callable from COBOL via:
 *   CALL "sql-exec"   USING BY REFERENCE WS-SQL-QUERY  WS-SQL-RESULT
 *   CALL "json-get"   USING BY REFERENCE WS-JSON WS-FIELD-NAME WS-FIELD-VALUE
 *   CALL "url-param"  USING BY REFERENCE WS-QUERY-STRING WS-PARAM-NAME WS-PARAM-VALUE
 *
 * All COBOL PIC X(N) fields arrive as N-byte, space-padded (not null-terminated).
 * Output fields are space-padded to their declared length before returning.
 */

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

/* ── helpers ──────────────────────────────────────────────────────────── */

static void rtrim(char *s, size_t max) {
    for (int i = (int)max - 1; i >= 0 && s[i] == ' '; i--)
        s[i] = '\0';
}

/* copy src into a fixed-size space-padded COBOL field */
static void to_cobol_field(const char *src, char *dst, size_t field_len) {
    size_t slen = strlen(src);
    if (slen > field_len) slen = field_len;
    memcpy(dst, src, slen);
    memset(dst + slen, ' ', field_len - slen);
}

/* growing string buffer */
typedef struct { char *buf; size_t len; size_t cap; } SBuf;

static void sb_append(SBuf *sb, const char *s) {
    size_t slen = strlen(s);
    while (sb->len + slen + 1 > sb->cap) {
        sb->cap = sb->cap ? sb->cap * 2 : 512;
        sb->buf = realloc(sb->buf, sb->cap);
    }
    memcpy(sb->buf + sb->len, s, slen);
    sb->len += slen;
    sb->buf[sb->len] = '\0';
}

static void sb_append_escaped(SBuf *sb, const char *s) {
    char ch[2] = {0, 0};
    for (; *s; s++) {
        switch (*s) {
            case '"':  sb_append(sb, "\\\""); break;
            case '\\': sb_append(sb, "\\\\"); break;
            case '\n': sb_append(sb, "\\n");  break;
            case '\r': sb_append(sb, "\\r");  break;
            case '\t': sb_append(sb, "\\t");  break;
            default:   ch[0] = *s; sb_append(sb, ch); break;
        }
    }
}

static const char *cobolgoat_db_path(void) {
    const char *env = getenv("COBOLGOAT_DB");
    if (env && *env) return env;
    if (access("/app/database/cobolgoat.db", F_OK) == 0)
        return "/app/database/cobolgoat.db";
    return "/tmp/cobol-goat/cobolgoat.db";
}

/* ── sql_exec ─────────────────────────────────────────────────────────── */
/*
 * COBOL interface:
 *   01 WS-SQL-QUERY   PIC X(1000).
 *   01 WS-SQL-RESULT  PIC X(16000).
 *   CALL "sql-exec" USING BY REFERENCE WS-SQL-QUERY  BY REFERENCE WS-SQL-RESULT
 *
 * WS-SQL-RESULT receives JSON: {"rows":[{...},...], "count": N}
 * or on error:               {"error": "message", "count": 0}
 *
 * VULNERABILITY: executes the query verbatim - SQL injection is the caller's problem.
 */
void sqlexec(char *query_field, char *result_field) {
    char query[1001];
    strncpy(query, query_field, 1000);
    query[1000] = '\0';
    rtrim(query, 1000);

    /* VULNERABILITY: log every query, including injected ones */
    FILE *log = fopen("/tmp/cobol-goat/sql.log", "a");
    if (log) { fprintf(log, "[SQL] %s\n", query); fclose(log); }

    sqlite3 *db;
    if (sqlite3_open(cobolgoat_db_path(), &db) != SQLITE_OK) {
        char err[200];
        snprintf(err, sizeof(err), "{\"error\": \"%s\", \"count\": 0}", sqlite3_errmsg(db));
        to_cobol_field(err, result_field, 16000);
        sqlite3_close(db);
        return;
    }

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        char err[500];
        snprintf(err, sizeof(err), "{\"error\": \"%s\", \"query\": \"%s\", \"count\": 0}",
                 sqlite3_errmsg(db), query);
        to_cobol_field(err, result_field, 16000);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    SBuf sb = {0};
    sb_append(&sb, "{\"rows\": [");

    int cols = sqlite3_column_count(stmt);
    int nrows = 0;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (nrows > 0) sb_append(&sb, ", ");
        sb_append(&sb, "{");
        for (int i = 0; i < cols; i++) {
            if (i > 0) sb_append(&sb, ", ");
            sb_append(&sb, "\"");
            sb_append(&sb, sqlite3_column_name(stmt, i));
            sb_append(&sb, "\": \"");
            const char *val = (const char *)sqlite3_column_text(stmt, i);
            if (val) sb_append_escaped(&sb, val);
            sb_append(&sb, "\"");
        }
        sb_append(&sb, "}");
        nrows++;
    }

    char tail[64];
    snprintf(tail, sizeof(tail), "], \"count\": %d}", nrows);
    sb_append(&sb, tail);

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    to_cobol_field(sb.buf, result_field, 16000);
    free(sb.buf);
}

/* ── json_get ─────────────────────────────────────────────────────────── */
/*
 * COBOL interface:
 *   01 WS-JSON        PIC X(4096).
 *   01 WS-FIELD-NAME  PIC X(64).
 *   01 WS-FIELD-VALUE PIC X(512).
 *   CALL "json-get" USING BY REFERENCE WS-JSON BY REFERENCE WS-FIELD-NAME
 *                         BY REFERENCE WS-FIELD-VALUE
 *
 * Simple extraction of "fieldname":"value" or "fieldname":value from JSON.
 */
void jsonget(char *json_field, char *name_field, char *value_field) {
    char json[4097], name[65];
    strncpy(json, json_field, 4096); json[4096] = '\0'; rtrim(json, 4096);
    strncpy(name, name_field, 64);   name[64]   = '\0'; rtrim(name, 64);

    memset(value_field, ' ', 512);

    /* find "name": optionally with spaces, then the value */
    char pattern[80];
    snprintf(pattern, sizeof(pattern), "\"%s\":", name);
    char *p = strstr(json, pattern);
    if (!p) return;
    p += strlen(pattern);
    while (*p == ' ') p++;  /* skip optional whitespace after : */

    char buf[513] = {0};
    int i = 0;
    if (*p == '"') {
        /* string value: read until closing unescaped quote */
        p++;
        while (*p && *p != '"' && i < 512) {
            if (*p == '\\') { p++; if (*p) buf[i++] = *p++; }
            else buf[i++] = *p++;
        }
    } else {
        /* number / boolean / null */
        while (*p && *p != ',' && *p != '}' && *p != ']' && i < 512)
            buf[i++] = *p++;
        while (i > 0 && buf[i-1] == ' ') buf[--i] = '\0';
    }
    to_cobol_field(buf, value_field, 512);
}

/* ── url_param ────────────────────────────────────────────────────────── */
/*
 * COBOL interface:
 *   01 WS-QUERY-STRING PIC X(4096).
 *   01 WS-PARAM-NAME   PIC X(64).
 *   01 WS-PARAM-VALUE  PIC X(1024).
 *   CALL "url-param" USING BY REFERENCE WS-QUERY-STRING BY REFERENCE WS-PARAM-NAME
 *                          BY REFERENCE WS-PARAM-VALUE
 *
 * Extracts and URL-decodes a parameter from QUERY_STRING.
 * e.g. "q=hello+world&page=1" with param "q" → "hello world"
 */
static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

void urlparam(char *qs_field, char *param_field, char *value_field) {
    char qs[4097], param[65];
    strncpy(qs, qs_field, 4096); qs[4096] = '\0'; rtrim(qs, 4096);
    strncpy(param, param_field, 64); param[64] = '\0'; rtrim(param, 64);

    memset(value_field, ' ', 1024);

    /* build search key: "param=" */
    char key[70];
    snprintf(key, sizeof(key), "%s=", param);

    char *p = qs;
    while (p && *p) {
        if (strncmp(p, key, strlen(key)) == 0) {
            p += strlen(key);
            char buf[1025] = {0};
            int i = 0;
            while (*p && *p != '&' && i < 1024) {
                if (*p == '+') { buf[i++] = ' '; p++; }
                else if (*p == '%' && hex_digit(p[1]) >= 0 && hex_digit(p[2]) >= 0) {
                    buf[i++] = (char)((hex_digit(p[1]) << 4) | hex_digit(p[2]));
                    p += 3;
                } else buf[i++] = *p++;
            }
            to_cobol_field(buf, value_field, 1024);
            return;
        }
        p = strchr(p, '&');
        if (p) p++;
    }
}
