      *> COBOLBank - Document Viewer CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Path traversal - filename appended to base path without sanitization
      *>      Payload: ../../etc/passwd reads /etc/passwd
      *>   2. Base path disclosed in error messages
      *>   3. No file type or extension restrictions
      *>   4. Reads any file the process user can access

       IDENTIFICATION DIVISION.
       PROGRAM-ID. FILE-READ.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
      *>     VULNERABILITY: ASSIGN TO DYNAMIC uses WS-FULL-PATH at
      *>       runtime - the path is fully user-controlled
           SELECT REPORT-FILE ASSIGN TO DYNAMIC WS-FULL-PATH
               ORGANIZATION IS LINE SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD  REPORT-FILE.
       01  REPORT-RECORD          PIC X(256).

       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-FILENAME             PIC X(256).

      *> VULNERABILITY: base path concatenated with unsanitized input
       01 WS-BASE-PATH            PIC X(32)
          VALUE "/app/reports/".
       01 WS-FULL-PATH            PIC X(512).

       01 WS-FILE-STATUS          PIC XX.
          88 FILE-OK              VALUE "00".
          88 FILE-NOT-FOUND       VALUE "35".

       01 WS-CONTENTS             PIC X(8192).
       01 WS-LINE-BUF             PIC X(256).
       01 WS-EOF                  PIC X VALUE "N".
          88 END-OF-FILE          VALUE "Y".
       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-FILENAME
           PERFORM BUILD-FILE-PATH
           PERFORM READ-FILE-CONTENTS
           PERFORM BUILD-RESPONSE
           STOP RUN.

      *>
       EXTRACT-FILENAME.
           MOVE "file" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-FILENAME.

      *>
      *> VULNERABILITY: No sanitization of WS-FILENAME
      *>   ../../etc/passwd resolves to /etc/passwd
      *>   ../../etc/shadow exposes password hashes (if readable)
      *>   ../../proc/self/environ exposes process environment
       BUILD-FILE-PATH.
           STRING
               FUNCTION TRIM(WS-BASE-PATH) DELIMITED SIZE
               FUNCTION TRIM(WS-FILENAME) DELIMITED SIZE
               INTO WS-FULL-PATH
           END-STRING.

      *>
      *> Real COBOL sequential file read using FILE SECTION
      *>   The ASSIGN TO DYNAMIC clause binds WS-FULL-PATH at OPEN time
       READ-FILE-CONTENTS.
           MOVE SPACES TO WS-CONTENTS
           MOVE "N" TO WS-EOF

           OPEN INPUT REPORT-FILE

           IF NOT FILE-OK
               MOVE "Y" TO WS-EOF
           END-IF

           PERFORM UNTIL END-OF-FILE
               READ REPORT-FILE INTO WS-LINE-BUF
                   AT END
                       MOVE "Y" TO WS-EOF
                   NOT AT END
                       STRING
                           FUNCTION TRIM(WS-CONTENTS) DELIMITED SIZE
                           FUNCTION TRIM(WS-LINE-BUF) DELIMITED SIZE
                           "\n"
                           DELIMITED SIZE
                           INTO WS-CONTENTS
                       END-STRING
               END-READ
           END-PERFORM

           CLOSE REPORT-FILE.

      *>
       BUILD-RESPONSE.
           STRING
               '{"path": "'
               FUNCTION TRIM(WS-FULL-PATH) DELIMITED SIZE
               '", "fileStatus": "'
               FUNCTION TRIM(WS-FILE-STATUS) DELIMITED SIZE
               '", "contents": "'
               FUNCTION TRIM(WS-CONTENTS) DELIMITED SIZE
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT
           END-STRING
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
