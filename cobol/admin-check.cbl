      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> admin-check.cbl - Authorization check with auth bypass vulnerabilities
      *>
      *> VULNERABILITIES:
      *>   1. Auth bypass - role comes from user-controlled CLI argument
      *>      Attacker simply passes role=admin to gain admin access
      *>   2. Missing function-level access control - string equality only
      *>   3. No session validation - no server-side session token checked
      *>   4. Audit log uses user-supplied data without validation
      *>   5. Privilege escalation - any user can claim any role

       IDENTIFICATION DIVISION.
       PROGRAM-ID. ADMIN-CHECK.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).
       01 WS-ARG3                 PIC X(256).

       01 WS-USER-ID              PIC X(64).

      *> VULNERABILITY: Role comes from user-controlled input (CLI arg)
      *> No server-side session lookup performed
      *> Attacker passes: admin-check 9999 admin delete_user
      *> And gains full admin access
       01 WS-ROLE                 PIC X(32).
       01 WS-ACTION               PIC X(64).

       01 WS-JSON-OUT             PIC X(512).
       01 WS-MKDIR-CMD            PIC X(64)
           VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-RESULT               PIC 99.
       01 WS-ALLOWED              PIC X VALUE "N".
       01 WS-AUDIT-CMD            PIC X(256).

      *> VULNERABILITY: Hardcoded role check - trivially bypassable
      *> Any caller who knows the magic string "admin" gets full access
       01 WS-ADMIN-ROLE           PIC X(5) VALUE "admin".
       01 WS-MOD-ROLE             PIC X(9) VALUE "moderator".

       PROCEDURE DIVISION.
       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-RESULT

           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 3
               DISPLAY '{"error": "Usage: admin-check <user_id>'
                   ' <role> <action>"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG3 FROM ARGUMENT-VALUE

           MOVE FUNCTION TRIM(WS-ARG1) TO WS-USER-ID
           MOVE FUNCTION TRIM(WS-ARG2) TO WS-ROLE
           MOVE FUNCTION TRIM(WS-ARG3) TO WS-ACTION

      *> VULNERABILITY: Auth bypass via user-controlled role parameter
      *> Role is read from command-line argument, not from server-side session
      *> Any user can pass role=admin to gain administrative privileges
      *> No token validation, no database lookup, no signature check
           IF FUNCTION TRIM(WS-ROLE) = FUNCTION TRIM(WS-ADMIN-ROLE)
               MOVE "Y" TO WS-ALLOWED
           ELSE
           IF FUNCTION TRIM(WS-ROLE) = FUNCTION TRIM(WS-MOD-ROLE)
      *>        VULNERABILITY: Moderators allowed same actions as admins
      *>        Missing function-level access control distinctions
               MOVE "Y" TO WS-ALLOWED
           ELSE
               MOVE "N" TO WS-ALLOWED
           END-IF
           END-IF

      *> VULNERABILITY: Audit log entry built from user-supplied values
      *> User can forge false audit trail by controlling action and userId
           STRING "echo '[AUDIT] User="
               FUNCTION TRIM(WS-USER-ID)
               " Role="
               FUNCTION TRIM(WS-ROLE)
               " Action="
               FUNCTION TRIM(WS-ACTION)
               " >> /tmp/cobol-goat/audit.log"
               DELIMITED SIZE
               INTO WS-AUDIT-CMD
           END-STRING
           CALL "SYSTEM" USING WS-AUDIT-CMD RETURNING WS-RESULT

           IF WS-ALLOWED = "Y"
               STRING '{"allowed": true, "action": "'
                   FUNCTION TRIM(WS-ACTION)
                   '", "userId": "'
                   FUNCTION TRIM(WS-USER-ID)
                   '", "role": "'
                   FUNCTION TRIM(WS-ROLE)
                   '", "auditLogged": true}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               END-STRING
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           ELSE
               STRING '{"allowed": false, "error": "Insufficient privileges"'
                   ', "action": "'
                   FUNCTION TRIM(WS-ACTION)
                   '", "userId": "'
                   FUNCTION TRIM(WS-USER-ID)
                   '", "role": "'
                   FUNCTION TRIM(WS-ROLE)
                   '"}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               END-STRING
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
               MOVE 1 TO RETURN-CODE
           END-IF

           STOP RUN.
