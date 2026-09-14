# COBOLBank - Multi-stage Docker build
#
# Stage 1: Build COBOL CGI programs
#   - GnuCOBOL compiles .cbl → native executables
#   - C SQLite bridge compiled and linked in
#
# Stage 2: Apache runtime (no Node.js)
#   - Only libcob4 (GnuCOBOL runtime) needed at runtime
#   - Apache mod_cgi serves COBOL binaries directly

# ── Builder ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gnucobol \
        gcc \
        make \
        libsqlite3-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY cobol/ ./cobol/

RUN cd /build/cobol && make all

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        libcob4 \
        libsqlite3-0 \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Enable required Apache modules
RUN a2enmod cgi rewrite headers

# Apache configuration
COPY apache/cobolbank.conf /etc/apache2/sites-available/cobolbank.conf
RUN a2dissite 000-default && a2ensite cobolbank

# COBOL CGI binaries
COPY --from=builder /build/cobol/cgi-bin/ /app/cobol/cgi-bin/

# GnuCOBOL module library — named .so files that GnuCOBOL loads via
# COB_LIBRARY_PATH when CALL "sql-exec" / "json-get" / "url-param" runs.
COPY --from=builder /build/cobol/lib/ /app/cobol/lib/

# Static frontend
COPY frontend/public/ /var/www/html/

# Database setup
COPY database/ /app/database/
RUN mkdir -p /app/database

# Entrypoint
COPY scripts/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Writable log and session directories
RUN mkdir -p /tmp/cobol-goat/sessions && chmod -R 777 /tmp/cobol-goat

# Reports directory for path traversal challenge
RUN mkdir -p /app/reports && \
    echo "Q3 Financial Summary - COBOLBank" > /app/reports/q3-summary.txt && \
    echo "Total Assets: \$4,821,003.44"   >> /app/reports/q3-summary.txt && \
    echo "Net Income:   \$1,200,411.00"   >> /app/reports/q3-summary.txt

# Apache listens on 80
EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
