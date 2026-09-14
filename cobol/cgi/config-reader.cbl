      *> COBOLBank - Configuration reader CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Unauthenticated - no credentials or session required
      *>   2. Hardcoded secrets embedded directly in WORKING-STORAGE
      *>      Visible in: binary strings, core dumps, memory scans
      *>   3. All secrets returned in a single unauthenticated response
      *>   4. AWS credentials, API keys, and encryption keys all exposed
      *>
      *> Real-world pattern: COBOL config programs on mainframes often
      *> embed credentials compiled into the binary. Any authorized user
      *> who can call the program (or read its memory) gets all secrets.

       IDENTIFICATION DIVISION.
       PROGRAM-ID. CONFIG-READER.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

      *> VULNERABILITY: Hardcoded credentials - compiled into binary
      *>   Extractable via: strings ./config-reader | grep -E 'pass|key|secret'
       01 CFG-DB-HOST             PIC X(32) VALUE "db.cobolbank.internal".
       01 CFG-DB-PORT             PIC X(8)  VALUE "5432".
       01 CFG-DB-NAME             PIC X(32) VALUE "cobolbank_prod".
       01 CFG-DB-USER             PIC X(32) VALUE "cobolbank_app".
       01 CFG-DB-PASSWORD         PIC X(32) VALUE "Sup3rS3cr3t!".
       01 CFG-API-KEY             PIC X(48)
              VALUE "sk-cobol-prod-8675309-abc123def456".
       01 CFG-ENCRYPT-KEY         PIC X(48)
              VALUE "AES256KEY1234567ABCDEFGHIJKLMNOP".
       01 CFG-JWT-SECRET          PIC X(48)
              VALUE "jwt-secret-do-not-share-123".
       01 CFG-SMTP-HOST           PIC X(32) VALUE "smtp.cobolbank.internal".
       01 CFG-SMTP-PASS           PIC X(32) VALUE "emailpass123".
       01 CFG-AWS-REGION          PIC X(16) VALUE "us-east-1".
       01 CFG-AWS-KEY             PIC X(32) VALUE "AKIAIOSFODNN7EXAMPLE".
       01 CFG-AWS-SECRET          PIC X(48)
              VALUE "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".
       01 CFG-MASTER-API-KEY      PIC X(48)
              VALUE "master-key-use-for-emergency-access-only-9999".

       01 WS-JSON-OUT             PIC X(4096).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

      *>     VULNERABILITY: No authentication check before this PERFORM
           PERFORM DUMP-ALL-CONFIG

           STOP RUN.

      *>
      *> VULNERABILITY: Dumps every secret in one unauthenticated call
       DUMP-ALL-CONFIG.
           STRING
               '{"environment": "production",'
               ' "database": {'
               '  "host": "'     FUNCTION TRIM(CFG-DB-HOST)     DELIMITED SIZE
               '", "port": "'    FUNCTION TRIM(CFG-DB-PORT)     DELIMITED SIZE
               '", "name": "'    FUNCTION TRIM(CFG-DB-NAME)     DELIMITED SIZE
               '", "user": "'    FUNCTION TRIM(CFG-DB-USER)     DELIMITED SIZE
               '", "password": "' FUNCTION TRIM(CFG-DB-PASSWORD) DELIMITED SIZE
               '"},'
               ' "apiKey": "'    FUNCTION TRIM(CFG-API-KEY)     DELIMITED SIZE
               '",'
               ' "encryptionKey": "' FUNCTION TRIM(CFG-ENCRYPT-KEY) DELIMITED SIZE
               '",'
               ' "jwtSecret": "' FUNCTION TRIM(CFG-JWT-SECRET)  DELIMITED SIZE
               '",'
               ' "smtp": {'
               '  "host": "'     FUNCTION TRIM(CFG-SMTP-HOST)   DELIMITED SIZE
               '", "password": "' FUNCTION TRIM(CFG-SMTP-PASS)  DELIMITED SIZE
               '"},'
               ' "aws": {'
               '  "region": "'   FUNCTION TRIM(CFG-AWS-REGION)  DELIMITED SIZE
               '", "accessKeyId": "' FUNCTION TRIM(CFG-AWS-KEY) DELIMITED SIZE
               '", "secretAccessKey": "'
               FUNCTION TRIM(CFG-AWS-SECRET) DELIMITED SIZE
               '"},'
               ' "masterApiKey": "' FUNCTION TRIM(CFG-MASTER-API-KEY) DELIMITED SIZE
               '"}'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING

           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
