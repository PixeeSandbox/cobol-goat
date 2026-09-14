      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> config-reader.cbl - Configuration reader with hardcoded secrets vulnerability
      *>
      *> VULNERABILITIES:
      *>   1. Hardcoded secrets in WORKING-STORAGE (source code)
      *>      DB password, API key, SMTP password, encryption key all in plaintext
      *>   2. All secrets exposed in JSON response regardless of auth
      *>   3. Encryption key exposed - makes encrypted data decryptable
      *>   4. Production API key hardcoded - can be extracted from binary with strings(1)
      *>   5. No access control on config endpoint

       IDENTIFICATION DIVISION.
       PROGRAM-ID. CONFIG-READER.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-CONFIG-KEY           PIC X(256).

      *> VULNERABILITY: Hardcoded secrets in WORKING-STORAGE
      *> These values are embedded in the compiled binary and visible via:
      *>   strings bin/config-reader | grep -E "(pass|key|secret)"
      *> They are also transmitted in cleartext in every API response
       01 WS-DB-HOST              PIC X(30) VALUE "db.internal".
       01 WS-DB-PORT              PIC X(5) VALUE "5432".
       01 WS-DB-NAME              PIC X(20) VALUE "cobolapp_prod".
       01 WS-DB-USER              PIC X(20) VALUE "cobolapp".

      *> VULNERABILITY: Production database password hardcoded
       01 WS-DB-PASSWORD          PIC X(20) VALUE "Sup3rS3cr3t!".

      *> VULNERABILITY: Production API key hardcoded
       01 WS-API-KEY              PIC X(40)
           VALUE "sk-cobol-prod-8675309-abc123def456".

      *> VULNERABILITY: SMTP credentials hardcoded
       01 WS-SMTP-HOST            PIC X(30) VALUE "smtp.cobolgoat.internal".
       01 WS-SMTP-USER            PIC X(30) VALUE "noreply@cobolgoat.internal".
       01 WS-SMTP-PASSWORD        PIC X(20) VALUE "emailpass123".

      *> VULNERABILITY: Encryption key hardcoded - compromises all encrypted data
       01 WS-ENCRYPTION-KEY       PIC X(20) VALUE "AES256KEY1234567".

      *> VULNERABILITY: JWT secret hardcoded
       01 WS-JWT-SECRET           PIC X(30) VALUE "jwt-secret-do-not-share-123".

       01 WS-JSON-OUT             PIC X(1024).

       PROCEDURE DIVISION.
       MAIN-PARA.
           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER

           IF WS-ARGC >= 1
               ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG1) TO WS-CONFIG-KEY
           ELSE
               MOVE SPACES TO WS-CONFIG-KEY
           END-IF

      *> VULNERABILITY: No authentication or authorization check
      *> Any process that can execute this binary gets all secrets
      *> No role check, no token validation, no IP restriction

      *> VULNERABILITY: Returns all secrets in one response
      *> Even if caller only requested DB_HOST, they get API keys too
           STRING '{"DB_HOST": "'
               FUNCTION TRIM(WS-DB-HOST)
               '", "DB_PORT": "'
               FUNCTION TRIM(WS-DB-PORT)
               '", "DB_NAME": "'
               FUNCTION TRIM(WS-DB-NAME)
               '", "DB_USER": "'
               FUNCTION TRIM(WS-DB-USER)
               '", "DB_PASSWORD": "'
               FUNCTION TRIM(WS-DB-PASSWORD)
               '", "API_KEY": "'
               FUNCTION TRIM(WS-API-KEY)
               '", "SMTP_HOST": "'
               FUNCTION TRIM(WS-SMTP-HOST)
               '", "SMTP_USER": "'
               FUNCTION TRIM(WS-SMTP-USER)
               '", "SMTP_PASSWORD": "'
               FUNCTION TRIM(WS-SMTP-PASSWORD)
               '", "ENCRYPTION_KEY": "'
               FUNCTION TRIM(WS-ENCRYPTION-KEY)
               '", "JWT_SECRET": "'
               FUNCTION TRIM(WS-JWT-SECRET)
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
