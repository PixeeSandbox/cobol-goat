      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> login.cbl - Authentication with multiple vulnerabilities
      *>
      *> VULNERABILITIES:
      *>   1. Hardcoded credentials in WORKING-STORAGE
      *>   2. SQL Injection - user input concatenated into query string
      *>   3. Sensitive data (password) logged in cleartext
      *>   4. No password hashing - plaintext comparison

       IDENTIFICATION DIVISION.
       PROGRAM-ID. LOGIN.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT AUTH-LOG ASSIGN TO "/tmp/cobol-goat/auth.log"
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD AUTH-LOG.
       01 AUTH-LOG-RECORD         PIC X(512).

       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).

      *> VULNERABILITY: Hardcoded credentials in source code
       01 WS-ADMIN-USER           PIC X(20) VALUE "admin".
       01 WS-ADMIN-PASS           PIC X(20) VALUE "c0b0ladm1n".

       01 WS-USERNAME             PIC X(256).
       01 WS-PASSWORD             PIC X(256).

      *> VULNERABILITY: SQL Injection - query built by string concatenation
       01 WS-QUERY                PIC X(512).
       01 WS-QUERY-PREFIX         PIC X(60)
           VALUE "SELECT * FROM USERS WHERE USERNAME = '".
       01 WS-QUERY-MID            PIC X(30)
           VALUE "' AND PASSWORD = '".
       01 WS-QUERY-SUFFIX         PIC X(2) VALUE "'".

       01 WS-JSON-OUT             PIC X(1024).
       01 WS-LOG-ENTRY            PIC X(512).
       01 WS-FILE-STATUS          PIC XX.
       01 WS-MKDIR-CMD            PIC X(64)
           VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-RESULT               PIC 99.

       PROCEDURE DIVISION.
       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-RESULT

           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 2
               DISPLAY '{"success": false, "error": "Usage: login'
                   ' <username> <password>"}'
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG2 FROM ARGUMENT-VALUE

           MOVE FUNCTION TRIM(WS-ARG1) TO WS-USERNAME
           MOVE FUNCTION TRIM(WS-ARG2) TO WS-PASSWORD

      *> VULNERABILITY: SQL Injection - input concatenated directly
           STRING FUNCTION TRIM(WS-QUERY-PREFIX)
               FUNCTION TRIM(WS-USERNAME)
               FUNCTION TRIM(WS-QUERY-MID)
               FUNCTION TRIM(WS-PASSWORD)
               FUNCTION TRIM(WS-QUERY-SUFFIX)
               DELIMITED SIZE
               INTO WS-QUERY
           END-STRING

      *> VULNERABILITY: Sensitive data (password) written to log in cleartext
           STRING "[AUTH] Login attempt - Username: "
               FUNCTION TRIM(WS-USERNAME)
               " Password: "
               FUNCTION TRIM(WS-PASSWORD)
               DELIMITED SIZE
               INTO WS-LOG-ENTRY
           END-STRING

           OPEN EXTEND AUTH-LOG
           MOVE WS-LOG-ENTRY TO AUTH-LOG-RECORD
           WRITE AUTH-LOG-RECORD
           CLOSE AUTH-LOG

      *> VULNERABILITY: Plaintext string comparison (no hashing)
           IF FUNCTION TRIM(WS-USERNAME) = FUNCTION TRIM(WS-ADMIN-USER)
               AND FUNCTION TRIM(WS-PASSWORD) =
                   FUNCTION TRIM(WS-ADMIN-PASS)
               STRING '{"success": true, "userId": "1", "role": "admin"'
                   ', "query": "'
                   FUNCTION TRIM(WS-QUERY)
                   '"}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           ELSE
               STRING '{"success": false, "error": "Invalid credentials"'
                   ', "query": "'
                   FUNCTION TRIM(WS-QUERY)
                   '"}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
               MOVE 1 TO RETURN-CODE
           END-IF

           STOP RUN.
