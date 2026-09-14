      *> COBOLBank - Login CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. SQL injection - STRING concatenates user input directly into query
      *>   2. Hardcoded admin credentials in WORKING-STORAGE
      *>   3. Plaintext password logging to /tmp/cobol-goat/auth.log
      *>   4. Full SQL query returned to caller in response

       IDENTIFICATION DIVISION.
       PROGRAM-ID. LOGIN.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

      *> VULNERABILITY: Hardcoded credentials embedded in binary
       01 WS-HARDCODED-USER       PIC X(16) VALUE "admin".
       01 WS-HARDCODED-PASS       PIC X(16) VALUE "c0b0ladm1n".

       01 WS-USERNAME             PIC X(64).
       01 WS-PASSWORD             PIC X(64).

       01 WS-USER-ID              PIC X(16).
       01 WS-USER-ROLE            PIC X(16).
       01 WS-ROW-COUNT            PIC X(8).

       01 WS-LOG-CMD              PIC X(256).
       01 WS-SYS-RESULT           PIC 99.

       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM READ-POST-BODY
           PERFORM WRITE-JSON-HEADER
           PERFORM EXTRACT-CREDENTIALS
           PERFORM LOG-AUTH-ATTEMPT
           PERFORM BUILD-LOGIN-QUERY
           CALL "sqlexec" USING BY REFERENCE WS-SQL-QUERY
                                 BY REFERENCE WS-SQL-RESULT
           PERFORM BUILD-RESPONSE
           STOP RUN.

       EXTRACT-CREDENTIALS.
           MOVE "username" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-USERNAME
           MOVE "password" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-PASSWORD.

      *> VULNERABILITY: Plaintext credentials written to log file
      *> Attacker with log access gains all user passwords
       LOG-AUTH-ATTEMPT.
           STRING "echo AUTH user="
               FUNCTION TRIM(WS-USERNAME) DELIMITED SIZE
               " pass="
               FUNCTION TRIM(WS-PASSWORD) DELIMITED SIZE
               " >> /tmp/cobol-goat/auth.log"
               DELIMITED SIZE INTO WS-LOG-CMD
           END-STRING
           CALL "SYSTEM" USING WS-LOG-CMD RETURNING WS-SYS-RESULT.

      *> VULNERABILITY: SQL injection via STRING concatenation
      *> Input:   admin' OR '1'='1' --
      *> Query:   SELECT ... WHERE username='admin' OR '1'='1' -- ...
      *> Result:  returns all rows; first row is typically admin
       BUILD-LOGIN-QUERY.
           STRING
               "SELECT id, username, role FROM users"
               " WHERE username='"
               FUNCTION TRIM(WS-USERNAME) DELIMITED SIZE
               "' AND password='"
               FUNCTION TRIM(WS-PASSWORD) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-SQL-QUERY
           END-STRING.

       BUILD-RESPONSE.
           MOVE "count" TO WS-SQL-FIELD
           CALL "jsonget" USING BY REFERENCE WS-SQL-RESULT
                                 BY REFERENCE WS-SQL-FIELD
                                 BY REFERENCE WS-SQL-VALUE
           MOVE FUNCTION TRIM(WS-SQL-VALUE) TO WS-ROW-COUNT

           MOVE "id" TO WS-SQL-FIELD
           CALL "jsonget" USING BY REFERENCE WS-SQL-RESULT
                                 BY REFERENCE WS-SQL-FIELD
                                 BY REFERENCE WS-USER-ID

           MOVE "role" TO WS-SQL-FIELD
           CALL "jsonget" USING BY REFERENCE WS-SQL-RESULT
                                 BY REFERENCE WS-SQL-FIELD
                                 BY REFERENCE WS-USER-ROLE

           EVALUATE TRUE
               WHEN WS-ROW-COUNT = "0" OR WS-SQL-VALUE = SPACES
                   STRING
                       '{"success": false,'
                       ' "error": "Invalid credentials",'
                       ' "query": "'
                       FUNCTION TRIM(WS-SQL-QUERY) DELIMITED SIZE
                       '"}'
                       DELIMITED SIZE INTO WS-JSON-OUT
                   END-STRING

               WHEN OTHER
                   STRING
                       '{"success": true,'
                       ' "userId": "'
                       FUNCTION TRIM(WS-USER-ID) DELIMITED SIZE
                       '", "username": "'
                       FUNCTION TRIM(WS-USERNAME) DELIMITED SIZE
                       '", "role": "'
                       FUNCTION TRIM(WS-USER-ROLE) DELIMITED SIZE
                       '", "query": "'
                       FUNCTION TRIM(WS-SQL-QUERY) DELIMITED SIZE
                       '"}'
                       DELIMITED SIZE INTO WS-JSON-OUT
                   END-STRING
           END-EVALUATE

           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
