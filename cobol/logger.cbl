      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> logger.cbl - Application logger with sensitive data exposure vulnerabilities
      *>
      *> VULNERABILITIES:
      *>   1. Sensitive data in logs - password logged in cleartext
      *>   2. Verbose debug logging - full request including credentials to debug.log
      *>   3. Log files world-readable (no permission restriction applied)
      *>   4. No log rotation - logs grow unbounded, may fill disk
      *>   5. Log injection - user-controlled message written verbatim to log
      *>      Attacker can inject fake log entries or newlines

       IDENTIFICATION DIVISION.
       PROGRAM-ID. LOGGER.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT APP-LOG ASSIGN TO "/tmp/cobol-goat/application.log"
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-APP-STATUS.

           SELECT DEBUG-LOG ASSIGN TO "/tmp/cobol-goat/debug.log"
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-DBG-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD APP-LOG.
       01 APP-LOG-RECORD          PIC X(512).

       FD DEBUG-LOG.
       01 DEBUG-LOG-RECORD        PIC X(1024).

       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).
       01 WS-ARG3                 PIC X(256).
       01 WS-ARG4                 PIC X(256).

       01 WS-LEVEL                PIC X(256).
       01 WS-MESSAGE              PIC X(256).
       01 WS-USERNAME             PIC X(256).

      *> VULNERABILITY: Password accepted as parameter and stored/logged
       01 WS-PASSWORD             PIC X(256).

       01 WS-APP-STATUS           PIC XX.
       01 WS-DBG-STATUS           PIC XX.
       01 WS-MKDIR-CMD            PIC X(64)
           VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-RESULT               PIC 99.

      *> VULNERABILITY: Timestamp hardcoded placeholder (no real clock used)
       01 WS-TIMESTAMP            PIC X(19) VALUE "2024-01-01 12:00:00".

      *> VULNERABILITY: Log entries include raw password in cleartext
       01 WS-APP-ENTRY            PIC X(512).
       01 WS-DEBUG-ENTRY          PIC X(1024).
       01 WS-JSON-OUT             PIC X(512).

       PROCEDURE DIVISION.
       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-RESULT

           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 2
               DISPLAY '{"error": "Usage: logger <level> <message>'
                   ' [username] [password]"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
           MOVE FUNCTION TRIM(WS-ARG1) TO WS-LEVEL
           MOVE FUNCTION TRIM(WS-ARG2) TO WS-MESSAGE

           IF WS-ARGC >= 3
               ACCEPT WS-ARG3 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG3) TO WS-USERNAME
           ELSE
               MOVE "anonymous" TO WS-USERNAME
           END-IF

      *> VULNERABILITY: Password accepted as plain argument and stored in memory
           IF WS-ARGC >= 4
               ACCEPT WS-ARG4 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG4) TO WS-PASSWORD
           ELSE
               MOVE "(none)" TO WS-PASSWORD
           END-IF

      *> VULNERABILITY: Full log entry including cleartext password written to app log
      *> Anyone with read access to /tmp/cobol-goat/application.log sees passwords
           STRING "["
               FUNCTION TRIM(WS-TIMESTAMP)
               "] "
               FUNCTION TRIM(WS-LEVEL)
               ": User login attempted. Username: "
               FUNCTION TRIM(WS-USERNAME)
               " Password: "
               FUNCTION TRIM(WS-PASSWORD)
               " Message: "
               FUNCTION TRIM(WS-MESSAGE)
               DELIMITED SIZE
               INTO WS-APP-ENTRY
           END-STRING

           OPEN EXTEND APP-LOG
           MOVE WS-APP-ENTRY TO APP-LOG-RECORD
           WRITE APP-LOG-RECORD
           CLOSE APP-LOG

      *> VULNERABILITY: Debug log contains even more detail including raw password
      *> Debug logs often have broader access permissions and longer retention
           STRING "["
               FUNCTION TRIM(WS-TIMESTAMP)
               "] DEBUG REQUEST DUMP:"
               " level="
               FUNCTION TRIM(WS-LEVEL)
               " message="
               FUNCTION TRIM(WS-MESSAGE)
               " username="
               FUNCTION TRIM(WS-USERNAME)
               " password="
               FUNCTION TRIM(WS-PASSWORD)
               " argc="
               WS-ARGC
               DELIMITED SIZE
               INTO WS-DEBUG-ENTRY
           END-STRING

           OPEN EXTEND DEBUG-LOG
           MOVE WS-DEBUG-ENTRY TO DEBUG-LOG-RECORD
           WRITE DEBUG-LOG-RECORD
           CLOSE DEBUG-LOG

           STRING '{"logged": true'
               ', "logFile": "/tmp/cobol-goat/application.log"'
               ', "debugLog": "/tmp/cobol-goat/debug.log"'
               ', "level": "'
               FUNCTION TRIM(WS-LEVEL)
               '", "entry": "'
               FUNCTION TRIM(WS-APP-ENTRY)
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
