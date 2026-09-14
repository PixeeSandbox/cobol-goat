#!/bin/bash
# Compile all COBOL programs

set -e

cd /build/cobol
mkdir -p bin

echo "Compiling COBOL programs..."

programs=(
    login
    account-lookup
    search
    transfer
    file-read
    report-gen
    admin-check
    interest-calc
    logger
    config-reader
)

for prog in "${programs[@]}"; do
    echo "  Compiling ${prog}.cbl..."
    cobc -x -o "bin/${prog}" "${prog}.cbl" 2>&1
    echo "  ✓ ${prog}"
done

echo "All programs compiled successfully."
