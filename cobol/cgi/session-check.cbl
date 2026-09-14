      *> COBOLBank - Session management CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Session tokens are sequential integers (predictable/enumerable)
      *>   2. Session data stored as plaintext files - no encryption
      *>   3. Session file path built from cookie value without sanitization
      *>      Path traversal: COBSESSID=../../etc/passwd reads arbitrary files
      *>   4. No session expiry - tokens are valid forever
      *>   5. No binding to IP address or user-agent (session hijacking trivial)
      *>   6. Session file world-readable in /tmp (any local user can read)

       IDENTIFICATION DIVISION.
       PROGRAM-ID. SESSION-CHECK.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
      *> VULNERABILITY: WS-SESSION-PATH built from unsanitized cookie value
           SELECT SESSION-FILE ASSIGN TO DYNAMIC WS-SESSION-PATH
                  ORGANIZATION IS LINE SEQUENTIAL
                  FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD SESSION-FILE.
       01 SESSION-RECORD          PIC X(256).

       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

      *> VULNERABILITY: Cookie value used directly in file path
       01 WS-SESSION-ID           PIC X(128).
       01 WS-SESSION-PATH         PIC X(256).

       01 WS-FILE-STATUS          PIC XX.
          88 FILE-OK              VALUE "00".
          88 FILE-EOF             VALUE "10".
          88 FILE-NOT-FOUND       VALUE "35".

       01 WS-SESSION-DATA.
          05 WS-SESS-USERNAME     PIC X(64) VALUE SPACES.
          05 WS-SESS-ROLE         PIC X(32) VALUE SPACES.
          05 WS-SESS-USER-ID      PIC X(16) VALUE SPACES.

      *> Field parsing scratch
       01 WS-LINE-KEY             PIC X(32).
       01 WS-LINE-VAL             PIC X(128).
       01 WS-EQ-POS               PIC 9(4).

       01 WS-JSON-OUT             PIC X(1024).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER
           PERFORM EXTRACT-SESSION-COOKIE
           PERFORM CHECK-SESSION
           STOP RUN.

      *>
      *> Parse COBSESSID=<value> out of the Cookie header
       EXTRACT-SESSION-COOKIE.
           MOVE SPACES TO WS-SESSION-ID
      *>     Simple scan for "COBSESSID=" in HTTP_COOKIE
           INSPECT CGI-HTTP-COOKIE
               TALLYING WS-EQ-POS FOR CHARACTERS BEFORE "COBSESSID="
           IF WS-EQ-POS < FUNCTION LENGTH(CGI-HTTP-COOKIE)
               MOVE CGI-HTTP-COOKIE(WS-EQ-POS + 11:64)
                   TO WS-SESSION-ID
      *>         Trim at semicolon or space
               INSPECT WS-SESSION-ID
                   REPLACING ALL ";" BY SPACES
                   AFTER INITIAL SPACE
           END-IF.

      *>
      *> VULNERABILITY: No sanitization of WS-SESSION-ID before building path
      *>   COBSESSID=../../etc/passwd traverses out of sessions directory
       CHECK-SESSION.
           IF FUNCTION TRIM(WS-SESSION-ID) = SPACES
               DISPLAY '{"authenticated": false,'
                   ' "error": "No session cookie"}'
               STOP RUN
           END-IF

      *>     VULNERABILITY: Direct path construction from cookie value
           STRING "/tmp/cobol-goat/sessions/"
               FUNCTION TRIM(WS-SESSION-ID) DELIMITED SIZE
               ".dat"
               DELIMITED SIZE INTO WS-SESSION-PATH
           END-STRING

           OPEN INPUT SESSION-FILE
           EVALUATE WS-FILE-STATUS
               WHEN "00"
                   PERFORM READ-SESSION-DATA
                   CLOSE SESSION-FILE
                   PERFORM BUILD-AUTH-RESPONSE
               WHEN "35"
                   DISPLAY '{"authenticated": false,'
                       ' "error": "Session not found",'
                       ' "hint": "Try COBSESSID=1 through 9999"}'
               WHEN OTHER
                   STRING '{"authenticated": false, "fileStatus": "'
                       WS-FILE-STATUS DELIMITED SIZE
                       '"}'
                       DELIMITED SIZE INTO WS-JSON-OUT
                   END-STRING
                   DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           END-EVALUATE.

      *>
      *> VULNERABILITY: Session file is plaintext KEY=VALUE pairs
      *>   Anyone who can read /tmp/cobol-goat/sessions/ has all sessions
       READ-SESSION-DATA.
           PERFORM UNTIL FILE-EOF
               READ SESSION-FILE INTO SESSION-RECORD
                   AT END SET FILE-EOF TO TRUE
                   NOT AT END
                       PERFORM PARSE-SESSION-LINE
               END-READ
           END-PERFORM.

      *>
       PARSE-SESSION-LINE.
           MOVE SPACES  TO WS-LINE-KEY WS-LINE-VAL
           MOVE ZERO    TO WS-EQ-POS
           INSPECT SESSION-RECORD
               TALLYING WS-EQ-POS FOR CHARACTERS BEFORE "="
           IF WS-EQ-POS > 0 AND WS-EQ-POS < 32
               MOVE SESSION-RECORD(1:WS-EQ-POS)        TO WS-LINE-KEY
               MOVE SESSION-RECORD(WS-EQ-POS + 2:128)  TO WS-LINE-VAL
               EVALUATE FUNCTION TRIM(WS-LINE-KEY)
                   WHEN "USERNAME"
                       MOVE FUNCTION TRIM(WS-LINE-VAL) TO WS-SESS-USERNAME
                   WHEN "ROLE"
                       MOVE FUNCTION TRIM(WS-LINE-VAL) TO WS-SESS-ROLE
                   WHEN "USERID"
                       MOVE FUNCTION TRIM(WS-LINE-VAL) TO WS-SESS-USER-ID
               END-EVALUATE
           END-IF.

      *>
       BUILD-AUTH-RESPONSE.
           STRING
               '{"authenticated": true,'
               ' "sessionId": "'
               FUNCTION TRIM(WS-SESSION-ID) DELIMITED SIZE
               '", "username": "'
               FUNCTION TRIM(WS-SESS-USERNAME) DELIMITED SIZE
               '", "role": "'
               FUNCTION TRIM(WS-SESS-ROLE) DELIMITED SIZE
               '", "userId": "'
               FUNCTION TRIM(WS-SESS-USER-ID) DELIMITED SIZE
               '", "warning": "Session never expires"}'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
