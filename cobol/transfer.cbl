      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> transfer.cbl - Fund transfer with multiple vulnerabilities
      *>
      *> VULNERABILITIES:
      *>   1. Integer overflow - PIC 9(8) wraps silently on large balances
      *>   2. No input validation - negative amounts allowed (reverse transfer)
      *>   3. No authentication - caller identity never verified
      *>   4. No atomicity - partial failure leaves inconsistent state
      *>   5. Race condition potential - no locking on flat file

       IDENTIFICATION DIVISION.
       PROGRAM-ID. TRANSFER.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT ACCOUNTS-FILE ASSIGN TO "/tmp/cobol-goat/accounts.dat"
               ORGANIZATION IS LINE SEQUENTIAL
               ACCESS MODE IS SEQUENTIAL
               FILE STATUS IS WS-FILE-STATUS.

       DATA DIVISION.
       FILE SECTION.
       FD ACCOUNTS-FILE.
       01 ACCOUNTS-RECORD         PIC X(80).

       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).
       01 WS-ARG3                 PIC X(256).

       01 WS-FROM-ACCT            PIC X(256).
       01 WS-TO-ACCT              PIC X(256).
       01 WS-AMOUNT-STR           PIC X(256).

      *> VULNERABILITY: Integer overflow - only 8 digits before decimal
      *> Balance max = 99999999.99; adding large amounts wraps silently
       01 WS-FROM-BAL             PIC 9(8)V99.
       01 WS-TO-BAL               PIC 9(8)V99.

      *> VULNERABILITY: Signed amount allowed - negative = reverse transfer
       01 WS-AMOUNT               PIC S9(8)V99.

       01 WS-FROM-BAL-DISP        PIC Z(8).99.
       01 WS-TO-BAL-DISP          PIC Z(8).99.
       01 WS-AMOUNT-DISP          PIC -Z(7).99.

       01 WS-FILE-STATUS          PIC XX.
       01 WS-MKDIR-CMD            PIC X(64)
           VALUE "mkdir -p /tmp/cobol-goat".
       01 WS-RESULT               PIC 99.
       01 WS-JSON-OUT             PIC X(512).

      *> Default account balances (used when file doesn't exist)
       01 WS-DEFAULT-FROM-BAL     PIC 9(8)V99 VALUE 15000.00.
       01 WS-DEFAULT-TO-BAL       PIC 9(8)V99 VALUE 5000.00.

      *> VULNERABILITY: No overflow detection flag - wrapping is silent
       01 WS-OVERFLOW-FLAG        PIC X VALUE "N".

       PROCEDURE DIVISION.
       MAIN-PARA.
           CALL "SYSTEM" USING WS-MKDIR-CMD RETURNING WS-RESULT

           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 3
               DISPLAY '{"error": "Usage: transfer <from_account>'
                   ' <to_account> <amount>"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG3 FROM ARGUMENT-VALUE

           MOVE FUNCTION TRIM(WS-ARG1) TO WS-FROM-ACCT
           MOVE FUNCTION TRIM(WS-ARG2) TO WS-TO-ACCT
           MOVE FUNCTION TRIM(WS-ARG3) TO WS-AMOUNT-STR

      *> VULNERABILITY: No authentication check
      *> Anyone can transfer from any account by just knowing the account number
      *> There is no session token, user ID check, or ownership verification

      *> VULNERABILITY: No input validation on amount
      *> Negative amounts are accepted, allowing reverse transfers
      *> e.g., transfer 1001 1002 -500 moves $500 FROM 1002 TO 1001
           MOVE FUNCTION NUMVAL(WS-AMOUNT-STR) TO WS-AMOUNT

           MOVE WS-DEFAULT-FROM-BAL TO WS-FROM-BAL
           MOVE WS-DEFAULT-TO-BAL TO WS-TO-BAL

      *> VULNERABILITY: Integer overflow - no range check before arithmetic
      *> If WS-FROM-BAL = 99999999.99 and WS-AMOUNT = -1.00,
      *> then WS-TO-BAL + 1.00 silently wraps to 00000000.00
           SUBTRACT WS-AMOUNT FROM WS-FROM-BAL
           ADD WS-AMOUNT TO WS-TO-BAL

      *> VULNERABILITY: No atomicity - file write could fail after first update
      *> leaving accounts in inconsistent state (no rollback mechanism)

           MOVE WS-FROM-BAL TO WS-FROM-BAL-DISP
           MOVE WS-TO-BAL   TO WS-TO-BAL-DISP
           MOVE WS-AMOUNT   TO WS-AMOUNT-DISP

           STRING '{"success": true'
               ', "fromAccount": "'
               FUNCTION TRIM(WS-FROM-ACCT)
               '", "toAccount": "'
               FUNCTION TRIM(WS-TO-ACCT)
               '", "transferred": "'
               FUNCTION TRIM(WS-AMOUNT-DISP)
               '", "fromBalance": "'
               FUNCTION TRIM(WS-FROM-BAL-DISP)
               '", "toBalance": "'
               FUNCTION TRIM(WS-TO-BAL-DISP)
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
