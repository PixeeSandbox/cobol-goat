      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> report-gen.cbl - Report generation with command injection vulnerability
      *>
      *> VULNERABILITIES:
      *>   1. Command Injection - report_type and email concatenated into shell command
      *>      Attacker can inject: monthly; cat /etc/passwd
      *>      Or via email: user@x.com; rm -rf /tmp/cobol-goat
      *>   2. Uses CALL "SYSTEM" with user-controlled input
      *>   3. No shell metacharacter escaping or validation
      *>   4. Runs shell with application privileges

       IDENTIFICATION DIVISION.
       PROGRAM-ID. REPORT-GEN.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT CMD-OUTPUT ASSIGN TO "/tmp/cobol-goat/report-out.tmp"
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD CMD-OUTPUT.
       01 CMD-OUTPUT-RECORD       PIC X(256).

       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).

       01 WS-REPORT-TYPE          PIC X(256).
       01 WS-EMAIL                PIC X(256).

      *> VULNERABILITY: Command Injection - shell command built from user input
      *> No sanitization of shell metacharacters: ; | & ` $ ( ) > < etc.
       01 WS-SHELL-CMD            PIC X(1024).
       01 WS-DISPLAY-CMD          PIC X(512).
       01 WS-ECHO-CMD             PIC X(1024).

       01 WS-FILE-STATUS          PIC XX.
       01 WS-RESULT               PIC 99.
       01 WS-MKDIR-CMD            PIC X(64)
           VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-OUTPUT               PIC X(512) VALUE SPACES.
       01 WS-TEMP-OUT             PIC X(512).
       01 WS-JSON-OUT             PIC X(1024).
       01 WS-EOF                  PIC X VALUE "N".

       PROCEDURE DIVISION.
       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-RESULT

           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 1
               DISPLAY '{"error": "Usage: report-gen <report_type>'
                   ' [email]"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           MOVE FUNCTION TRIM(WS-ARG1) TO WS-REPORT-TYPE

           IF WS-ARGC >= 2
               ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG2) TO WS-EMAIL
           ELSE
               MOVE "noreply@cobolgoat.local" TO WS-EMAIL
           END-IF

      *> VULNERABILITY: Command Injection
      *> WS-REPORT-TYPE and WS-EMAIL flow directly into shell command
      *> Attacker input for report_type: monthly; id; echo
      *> Result executes: generate_report.sh monthly; id; echo | mail ...
      *>
      *> Attacker input for email: x@x.com; cat /etc/shadow > /tmp/leak
      *> Result: ... | mail -s 'Report' x@x.com; cat /etc/shadow > /tmp/leak
           STRING "generate_report.sh "
               FUNCTION TRIM(WS-REPORT-TYPE)
               " | mail -s 'Report' "
               FUNCTION TRIM(WS-EMAIL)
               DELIMITED SIZE
               INTO WS-DISPLAY-CMD
           END-STRING

      *> Actually execute: /bin/echo with report_type (injection demo via echo)
      *> This allows demonstrating injection: monthly; ls / still runs ls
           STRING "/bin/echo REPORT: "
               FUNCTION TRIM(WS-REPORT-TYPE)
               " > /tmp/cobol-goat/report-out.tmp 2>&1"
               DELIMITED SIZE
               INTO WS-ECHO-CMD
           END-STRING

      *> VULNERABILITY: CALL "SYSTEM" with unvalidated user input
      *> The report type is passed directly to the shell
           CALL "SYSTEM" USING WS-ECHO-CMD RETURNING WS-RESULT

      *> Read command output
           MOVE SPACES TO WS-OUTPUT
           MOVE "N" TO WS-EOF

           OPEN INPUT CMD-OUTPUT
           IF WS-FILE-STATUS = "00"
               PERFORM UNTIL WS-EOF = "Y"
                   READ CMD-OUTPUT INTO CMD-OUTPUT-RECORD
                       AT END
                           MOVE "Y" TO WS-EOF
                       NOT AT END
                           IF WS-OUTPUT = SPACES
                               MOVE FUNCTION TRIM(CMD-OUTPUT-RECORD)
                                   TO WS-OUTPUT
                           ELSE
                               STRING FUNCTION TRIM(WS-OUTPUT)
                                   " "
                                   FUNCTION TRIM(CMD-OUTPUT-RECORD)
                                   DELIMITED SIZE
                                   INTO WS-TEMP-OUT
                               MOVE WS-TEMP-OUT TO WS-OUTPUT
                           END-IF
                   END-READ
               END-PERFORM
               CLOSE CMD-OUTPUT
           END-IF

           IF WS-OUTPUT = SPACES
               MOVE "(no output)" TO WS-OUTPUT
           END-IF

           STRING '{"command": "'
               FUNCTION TRIM(WS-DISPLAY-CMD)
               '", "executed": "/bin/echo REPORT: '
               FUNCTION TRIM(WS-REPORT-TYPE)
               '", "output": "'
               FUNCTION TRIM(WS-OUTPUT)
               '", "exitCode": '
               WS-RESULT
               ', "success": true}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
