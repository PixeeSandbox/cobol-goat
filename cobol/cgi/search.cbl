      *> COBOLBank - Transaction Search CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. SQL injection in LIKE clause via STRING concatenation
      *>   2. UNION injection can dump any table (including users+passwords)
      *>   3. Search query and full result set returned to caller
      *>   4. No rate limiting, no authentication required

       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEARCH.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-SEARCH-TERM          PIC X(256).
       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-SEARCH-TERM
           PERFORM BUILD-SEARCH-QUERY
           CALL "sqlexec" USING BY REFERENCE WS-SQL-QUERY
                                 BY REFERENCE WS-SQL-RESULT
           PERFORM BUILD-RESPONSE
           STOP RUN.

      *>
       EXTRACT-SEARCH-TERM.
           MOVE "q" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-SEARCH-TERM.

      *>
      *> VULNERABILITY: SQL injection in LIKE clause
      *>
      *>   Normal use:   q=alice
      *>   Safe query:   SELECT ... WHERE username LIKE '%alice%'
      *>
      *>   Attack:       q=%' UNION SELECT id,username,password,role
      *>                      FROM users --
      *>   Injected:     SELECT id, username, email FROM users
      *>                 WHERE username LIKE '%%'
      *>                 UNION SELECT id,username,password,role
      *>                 FROM users --%'
      *>
      *>   The UNION returns all usernames and plaintext passwords.
      *>   The column count (3) must match the original SELECT.
       BUILD-SEARCH-QUERY.
           STRING
               "SELECT id, username, email FROM users"
               " WHERE username LIKE '%"
               FUNCTION TRIM(WS-SEARCH-TERM) DELIMITED SIZE
               "%'"
               DELIMITED SIZE
               INTO WS-SQL-QUERY
           END-STRING.

      *>
       BUILD-RESPONSE.
           STRING
               '{"query": "'
               FUNCTION TRIM(WS-SQL-QUERY) DELIMITED SIZE
               '", "result": '
               FUNCTION TRIM(WS-SQL-RESULT) DELIMITED SIZE
               '}'
               DELIMITED SIZE
               INTO WS-JSON-OUT
           END-STRING
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
