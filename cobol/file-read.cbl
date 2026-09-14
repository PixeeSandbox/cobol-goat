      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> file-read.cbl - File reading with path traversal vulnerability
      *>
      *> VULNERABILITIES:
      *>   1. Path Traversal - filename concatenated to base path without sanitization
      *>      Attacker can use: ../../etc/passwd to read arbitrary files
      *>      Or: ../../tmp/cobol-goat/auth.log to read credential logs
      *>   2. No filename validation - no check for ../ sequences
      *>   3. Runs as application user - may access sensitive system files

       IDENTIFICATION DIVISION.
       PROGRAM-ID. FILE-READ.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT TARGET-FILE ASSIGN TO WS-FULL-PATH
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD TARGET-FILE.
       01 TARGET-RECORD           PIC X(256).

       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).

       01 WS-FILENAME             PIC X(256).
       01 WS-USERNAME             PIC X(256).

      *> VULNERABILITY: Path Traversal - base path + user input without sanitization
      *> Attacker passes: ../../etc/passwd
      *> Result: /app/reports/../../etc/passwd = /etc/passwd
       01 WS-BASE-PATH            PIC X(20) VALUE "/app/reports/".
       01 WS-FULL-PATH            PIC X(512).

       01 WS-FILE-STATUS          PIC XX.
       01 WS-CONTENTS             PIC X(512) VALUE SPACES.
       01 WS-LINE-COUNT           PIC 99 VALUE 0.
       01 WS-CHARS-READ           PIC 9(4) VALUE 0.
       01 WS-JSON-OUT             PIC X(1024).
       01 WS-EOF                  PIC X VALUE "N".
       01 WS-TEMP-CONTENTS        PIC X(512).

       PROCEDURE DIVISION.
       MAIN-PARA.
           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 1
               DISPLAY '{"error": "Usage: file-read <filename>'
                   ' [username]"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           MOVE FUNCTION TRIM(WS-ARG1) TO WS-FILENAME

           IF WS-ARGC >= 2
               ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG2) TO WS-USERNAME
           ELSE
               MOVE "anonymous" TO WS-USERNAME
           END-IF

      *> VULNERABILITY: Path Traversal
      *> No sanitization of WS-FILENAME - ../ sequences are not stripped
      *> No canonicalization or realpath check performed
      *> No allowlist of permitted files or directories
           STRING FUNCTION TRIM(WS-BASE-PATH)
               FUNCTION TRIM(WS-FILENAME)
               DELIMITED SIZE
               INTO WS-FULL-PATH
           END-STRING

           OPEN INPUT TARGET-FILE
           IF WS-FILE-STATUS NOT = "00"
               STRING '{"error": "File not found", "filename": "'
                   FUNCTION TRIM(WS-FILENAME)
                   '", "path": "'
                   FUNCTION TRIM(WS-FULL-PATH)
                   '", "requestedBy": "'
                   FUNCTION TRIM(WS-USERNAME)
                   '"}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           MOVE SPACES TO WS-CONTENTS
           MOVE "N" TO WS-EOF
           MOVE 0 TO WS-CHARS-READ

           PERFORM UNTIL WS-EOF = "Y" OR WS-CHARS-READ >= 500
               READ TARGET-FILE INTO TARGET-RECORD
                   AT END
                       MOVE "Y" TO WS-EOF
                   NOT AT END
                       IF WS-CHARS-READ = 0
                           MOVE FUNCTION TRIM(TARGET-RECORD)
                               TO WS-CONTENTS
                       ELSE
                           STRING FUNCTION TRIM(WS-CONTENTS)
                               " | "
                               FUNCTION TRIM(TARGET-RECORD)
                               DELIMITED SIZE
                               INTO WS-TEMP-CONTENTS
                           MOVE WS-TEMP-CONTENTS TO WS-CONTENTS
                       END-IF
                       ADD FUNCTION LENGTH(
                           FUNCTION TRIM(TARGET-RECORD))
                           TO WS-CHARS-READ
               END-READ
           END-PERFORM

           CLOSE TARGET-FILE

           STRING '{"filename": "'
               FUNCTION TRIM(WS-FILENAME)
               '", "path": "'
               FUNCTION TRIM(WS-FULL-PATH)
               '", "requestedBy": "'
               FUNCTION TRIM(WS-USERNAME)
               '", "contents": "'
               FUNCTION TRIM(WS-CONTENTS)
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
