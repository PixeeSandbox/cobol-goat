# COBOLBank - COBOL CGI build system
#
# GnuCOBOL resolves CALL "sql-exec" at runtime by searching COB_LIBRARY_PATH
# for a file named "sql-exec.so", then dlsym-ing the symbol (hyphen→underscore).
# We build one shared library and symlink it under all three CALL names.

CC       = gcc
COBC     = cobc
CFLAGS   = -fPIC -O2 $(shell pkg-config --cflags sqlite3 2>/dev/null || echo "")
COBFLAGS = -x -free -I copybooks/

SQLITE_LIBS = $(shell pkg-config --libs sqlite3 2>/dev/null || echo "-lsqlite3")
CGI_OUT     = cgi-bin

PROGRAMS = login account-lookup search transfer file-read \
           report-gen admin-check interest-calc config-reader \
           debug session-check

COB_MODULES = lib/sqlexec.so lib/jsonget.so lib/urlparam.so

.PHONY: all clean dirs

all: dirs $(COB_MODULES) $(addprefix $(CGI_OUT)/,$(PROGRAMS))

dirs:
	mkdir -p $(CGI_OUT)

lib/libcobolsql.so: lib/cobol-sqlite.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(SQLITE_LIBS)

lib/sqlexec.so: lib/libcobolsql.so
	cp $< $@

lib/jsonget.so: lib/libcobolsql.so
	cp $< $@

lib/urlparam.so: lib/libcobolsql.so
	cp $< $@

# COBOL CGI programs do not link the C bridge at compile time;
# GnuCOBOL loads the named .so files from COB_LIBRARY_PATH at runtime.
$(CGI_OUT)/%: cgi/%.cbl copybooks/*.cpy
	$(COBC) $(COBFLAGS) -o $@ $<
	chmod 755 $@

clean:
	rm -f lib/libcobolsql.so $(COB_MODULES) $(addprefix $(CGI_OUT)/,$(PROGRAMS))

# ── Demo targets ────────────────────────────────────────────────────────────
demo-config:
	@echo "=== Unauthenticated config endpoint ==="
	COB_LIBRARY_PATH=lib \
	REQUEST_METHOD=GET \
	QUERY_STRING="" \
	COBOLGOAT_DB=/app/database/cobolgoat.db \
	$(CGI_OUT)/config-reader

demo-auth-bypass:
	@echo "=== Auth Bypass: pass role=admin ==="
	COB_LIBRARY_PATH=lib \
	QUERY_STRING="userId=99&role=admin&action=delete_user" \
	REQUEST_METHOD=GET \
	COBOLGOAT_DB=/app/database/cobolgoat.db \
	$(CGI_OUT)/admin-check
