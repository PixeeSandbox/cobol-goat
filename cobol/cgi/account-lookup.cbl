      *> COBOLBank - Account Lookup CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. IDOR - account ID taken from request, no ownership check
      *>   2. userId supplied by caller, not from server session
      *>   3. SQL injection on account ID parameter
      *>   4. SSN exposed in every response without masking
      *>   5. Query string returned to caller (information disclosure)

       IDENTIFICATION DIVISION.
       PROGRAM-ID. ACCOUNT-LOOKUP.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-ACCOUNT-ID           PIC X(64).
       01 WS-USER-ID              PIC X(64).
       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-PARAMS
           PERFORM BUILD-ACCOUNT-QUERY
           CALL "sqlexec" USING BY REFERENCE WS-SQL-QUERY
                                 BY REFERENCE WS-SQL-RESULT
           PERFORM BUILD-RESPONSE
           STOP RUN.

      *>
      *> VULNERABILITY: Both account ID and user ID come from the
      *>   caller - no server-side session is consulted at any point.
      *>   Any user can supply any userId and access any accountId.
       EXTRACT-PARAMS.
           MOVE "id" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-ACCOUNT-ID

      *>     VULNERABILITY: userId from request, not from session
           MOVE "userId" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-USER-ID.

      *>
      *> VULNERABILITY: SQL injection - account ID concatenated directly
      *>   Payload: id=1001' OR '1'='1  returns all accounts
      *>   Payload: id=1001' UNION SELECT id,username,password,role
      *>             FROM users -- leaks credentials
      *>
      *> VULNERABILITY: No ownership check - query does NOT include
      *>   AND owner = '<userId>' so any account is accessible
       BUILD-ACCOUNT-QUERY.
           STRING
               "SELECT id, owner, balance, ssn FROM accounts"
               " WHERE id='"
               FUNCTION TRIM(WS-ACCOUNT-ID) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-SQL-QUERY
           END-STRING.

      *>
      *> VULNERABILITY: SSN returned to caller regardless of role,
      *>   ownership, or authentication status
       BUILD-RESPONSE.
           STRING
               '{"accountId": "'
               FUNCTION TRIM(WS-ACCOUNT-ID) DELIMITED SIZE
               '", "requestedBy": "'
               FUNCTION TRIM(WS-USER-ID) DELIMITED SIZE
               '", "query": "'
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
