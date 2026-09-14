      *> COBOLBank - Admin action authorization CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Auth bypass - role comes from user-controlled query parameter
      *>   2. Any caller can pass role=admin to gain full access
      *>   3. Hardcoded role check - trivially bypassable string comparison
      *>   4. Audit log forged with user-supplied values (no integrity)
      *>   5. No session token validation whatsoever

       IDENTIFICATION DIVISION.
       PROGRAM-ID. ADMIN-CHECK.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-USER-ID              PIC X(64).
      *> VULNERABILITY: Role arrives from query string, not from a
      *>   server-side session lookup. Attacker simply supplies role=admin.
       01 WS-ROLE                 PIC X(32).
       01 WS-ACTION               PIC X(64).
       01 WS-ALLOWED              PIC X VALUE "N".
          88 ACTION-ALLOWED       VALUE "Y".

      *> VULNERABILITY: Hardcoded role names - attacker only needs to
      *>   know these strings to bypass all access controls
       01 WS-ADMIN-ROLE           PIC X(5)  VALUE "admin".
       01 WS-MOD-ROLE             PIC X(9)  VALUE "moderator".

       01 WS-AUDIT-CMD            PIC X(512).
       01 WS-SYS-RESULT           PIC 99.
       01 WS-MKDIR-CMD            PIC X(64)
              VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-JSON-OUT             PIC X(1024).

       PROCEDURE DIVISION.

       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-SYS-RESULT

           PERFORM READ-CGI-VARS
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-PARAMS
           PERFORM CHECK-AUTHORIZATION
           PERFORM WRITE-AUDIT-LOG
           PERFORM BUILD-RESPONSE

           STOP RUN.

      *>
       EXTRACT-PARAMS.
      *> VULNERABILITY: All three values come from untrusted query string
           MOVE "userId" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-USER-ID

           MOVE "role" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-ROLE

           MOVE "action" TO CGI-PARAM-NAME
           PERFORM GET-QUERY-PARAM
           MOVE FUNCTION TRIM(CGI-PARAM-VALUE) TO WS-ACTION.

      *>
      *> VULNERABILITY: Authorization decided purely by comparing a
      *>   user-supplied string against a hardcoded constant.
      *>   No cryptographic token, no database lookup, no signature.
       CHECK-AUTHORIZATION.
           EVALUATE FUNCTION TRIM(WS-ROLE)
               WHEN FUNCTION TRIM(WS-ADMIN-ROLE)
                   MOVE "Y" TO WS-ALLOWED
               WHEN FUNCTION TRIM(WS-MOD-ROLE)
      *>             VULNERABILITY: Moderators granted same access as admins
      *>             Missing function-level access control distinctions
                   MOVE "Y" TO WS-ALLOWED
               WHEN OTHER
                   MOVE "N" TO WS-ALLOWED
           END-EVALUATE.

      *>
      *> VULNERABILITY: Audit log built entirely from attacker-supplied
      *>   values. Attacker can write arbitrary entries to impersonate
      *>   other users or cover their tracks.
       WRITE-AUDIT-LOG.
           STRING "echo AUDIT User="
               FUNCTION TRIM(WS-USER-ID) DELIMITED SIZE
               " Role="
               FUNCTION TRIM(WS-ROLE) DELIMITED SIZE
               " Action="
               FUNCTION TRIM(WS-ACTION) DELIMITED SIZE
               " >> /tmp/cobol-goat/audit.log"
               DELIMITED SIZE INTO WS-AUDIT-CMD
           END-STRING
           CALL "SYSTEM" USING WS-AUDIT-CMD RETURNING WS-SYS-RESULT.

      *>
       BUILD-RESPONSE.
           IF ACTION-ALLOWED
               STRING
                   '{"allowed": true,'
                   ' "action": "'
                   FUNCTION TRIM(WS-ACTION) DELIMITED SIZE
                   '", "userId": "'
                   FUNCTION TRIM(WS-USER-ID) DELIMITED SIZE
                   '", "role": "'
                   FUNCTION TRIM(WS-ROLE) DELIMITED SIZE
                   '", "auditLogged": true}'
                   DELIMITED SIZE INTO WS-JSON-OUT
               END-STRING
           ELSE
               STRING
                   '{"allowed": false,'
                   ' "error": "Insufficient privileges",'
                   ' "action": "'
                   FUNCTION TRIM(WS-ACTION) DELIMITED SIZE
                   '", "userId": "'
                   FUNCTION TRIM(WS-USER-ID) DELIMITED SIZE
                   '", "role": "'
                   FUNCTION TRIM(WS-ROLE) DELIMITED SIZE
                   '", "hint": "Try role=admin"}'
                   DELIMITED SIZE INTO WS-JSON-OUT
               END-STRING
           END-IF

           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
