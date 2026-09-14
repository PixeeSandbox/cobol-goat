      *> COBOLBank - Debug information CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Unauthenticated - anyone can call this endpoint
      *>   2. Exposes all process environment variables (type=env)
      *>      Leaks DB_PASSWORD, API_KEY, and other secrets from environment
      *>   3. Exposes application log files (type=logs)
      *>      auth.log contains plaintext username/password pairs
      *>   4. Left enabled in production (classic debug endpoint exposure)

       IDENTIFICATION DIVISION.
       PROGRAM-ID. DEBUG.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
      *> VULNERABILITY: log file path is predictable; contents are sensitive
           SELECT LOG-FILE ASSIGN TO DYNAMIC WS-LOG-PATH
                  ORGANIZATION IS LINE SEQUENTIAL
                  FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD LOG-FILE.
       01 LOG-RECORD              PIC X(512).

       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-TYPE                 PIC X(32).
       01 WS-LOG-PATH             PIC X(128).
       01 WS-FILE-STATUS          PIC XX.
          88 FILE-OK              VALUE "00".
          88 FILE-EOF             VALUE "10".
       01 WS-LOG-CONTENTS         PIC X(8000) VALUE SPACES.
       01 WS-LOG-POS              PIC 9(6) VALUE 1.
       01 WS-RECORD-LEN           PIC 9(4).

       01 WS-ENV-PATH             PIC X(512).
       01 WS-ENV-HOME             PIC X(128).
       01 WS-ENV-USER             PIC X(64).
       01 WS-ENV-DB-PASS          PIC X(64).
       01 WS-ENV-API-KEY          PIC X(128).
       01 WS-ENV-COBOLGOAT-DB     PIC X(256).
       01 WS-ENV-SHELL            PIC X(128).

       01 WS-JSON-OUT             PIC X(16000) VALUE SPACES.
       01 WS-JSON-TMP             PIC X(512).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

           MOVE "type" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-TYPE

      *>     VULNERABILITY: No auth check before any branch
           EVALUATE FUNCTION TRIM(WS-TYPE)
               WHEN "env"  PERFORM DUMP-ENVIRONMENT
               WHEN "logs" PERFORM DUMP-LOGS
               WHEN "db"   PERFORM DUMP-DB-INFO
               WHEN OTHER  PERFORM DUMP-MENU
           END-EVALUATE

           STOP RUN.

      *>
      *> VULNERABILITY: Reads and returns sensitive environment variables
      *>   Leaks anything set via docker-compose environment: section
       DUMP-ENVIRONMENT.
           ACCEPT WS-ENV-PATH         FROM ENVIRONMENT "PATH"
           ACCEPT WS-ENV-HOME         FROM ENVIRONMENT "HOME"
           ACCEPT WS-ENV-USER         FROM ENVIRONMENT "USER"
           ACCEPT WS-ENV-DB-PASS      FROM ENVIRONMENT "DB_PASSWORD"
           ACCEPT WS-ENV-API-KEY      FROM ENVIRONMENT "API_KEY"
           ACCEPT WS-ENV-COBOLGOAT-DB FROM ENVIRONMENT "COBOLGOAT_DB"
           ACCEPT WS-ENV-SHELL        FROM ENVIRONMENT "SHELL"

           STRING
               '{"type": "env", "variables": {'
               ' "PATH": "'
               FUNCTION TRIM(WS-ENV-PATH) DELIMITED SIZE
               '", "HOME": "'
               FUNCTION TRIM(WS-ENV-HOME) DELIMITED SIZE
               '", "USER": "'
               FUNCTION TRIM(WS-ENV-USER) DELIMITED SIZE
               '", "DB_PASSWORD": "'
               FUNCTION TRIM(WS-ENV-DB-PASS) DELIMITED SIZE
               '", "API_KEY": "'
               FUNCTION TRIM(WS-ENV-API-KEY) DELIMITED SIZE
               '", "COBOLGOAT_DB": "'
               FUNCTION TRIM(WS-ENV-COBOLGOAT-DB) DELIMITED SIZE
               '", "SHELL": "'
               FUNCTION TRIM(WS-ENV-SHELL) DELIMITED SIZE
               '"}}'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING

           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

      *>
      *> VULNERABILITY: Exposes log files containing plaintext passwords
       DUMP-LOGS.
           STRING '{"type": "logs", "files": {"auth.log": "'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING

           MOVE "/tmp/cobol-goat/auth.log" TO WS-LOG-PATH
           PERFORM READ-LOG-FILE

           STRING FUNCTION TRIM(WS-JSON-OUT) DELIMITED SIZE
               FUNCTION TRIM(WS-LOG-CONTENTS) DELIMITED SIZE
               '", "sql.log": "'
               DELIMITED SIZE INTO WS-JSON-TMP
           END-STRING
           MOVE WS-JSON-TMP TO WS-JSON-OUT

           MOVE SPACES TO WS-LOG-CONTENTS
           MOVE 1      TO WS-LOG-POS
           MOVE "/tmp/cobol-goat/sql.log" TO WS-LOG-PATH
           PERFORM READ-LOG-FILE

           STRING FUNCTION TRIM(WS-JSON-OUT) DELIMITED SIZE
               FUNCTION TRIM(WS-LOG-CONTENTS) DELIMITED SIZE
               '"}}'
               DELIMITED SIZE INTO WS-JSON-TMP
           END-STRING

           DISPLAY FUNCTION TRIM(WS-JSON-TMP).

      *>
       READ-LOG-FILE.
           MOVE SPACES TO WS-LOG-CONTENTS
           MOVE 1      TO WS-LOG-POS
           OPEN INPUT LOG-FILE
           IF NOT FILE-OK
               MOVE "(log not found)" TO WS-LOG-CONTENTS
           ELSE
               PERFORM UNTIL FILE-EOF OR WS-LOG-POS > 7500
                   READ LOG-FILE INTO LOG-RECORD
                       AT END SET FILE-EOF TO TRUE
                       NOT AT END
                           MOVE FUNCTION LENGTH(
                               FUNCTION TRIM(LOG-RECORD))
                               TO WS-RECORD-LEN
                           STRING
                               WS-LOG-CONTENTS(1:WS-LOG-POS - 1)
                               FUNCTION TRIM(LOG-RECORD) DELIMITED SIZE
                               "\n"
                               DELIMITED SIZE
                               INTO WS-LOG-CONTENTS
                           END-STRING
                           ADD WS-RECORD-LEN 1 TO WS-LOG-POS
                   END-READ
               END-PERFORM
               CLOSE LOG-FILE
           END-IF.

      *>
       DUMP-DB-INFO.
           ACCEPT WS-ENV-COBOLGOAT-DB FROM ENVIRONMENT "COBOLGOAT_DB"
           STRING
               '{"type": "db",'
               ' "path": "'
               FUNCTION TRIM(WS-ENV-COBOLGOAT-DB) DELIMITED SIZE
               '", "note": "Use type=logs to see query log"}'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

      *>
       DUMP-MENU.
           DISPLAY '{"type": "menu", "available": ['
               '"env", "logs", "db"'
               '], "usage": "/cgi-bin/debug?type=env"}'.

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
