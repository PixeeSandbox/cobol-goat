      *> COBOLBank - Funds Transfer CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. No authentication - any caller can drain any account
      *>   2. No CSRF protection on this state-changing POST endpoint
      *>   3. Negative amount accepted - reverses the transfer direction
      *>   4. PIC 9(8)V99 silent overflow - balance wraps to near-zero
      *>   5. SQL injection on account IDs via STRING concatenation
      *>   6. Transfer executes without confirmation or approval

       IDENTIFICATION DIVISION.
       PROGRAM-ID. TRANSFER.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

       01 WS-FROM-ACCOUNT         PIC X(64).
       01 WS-TO-ACCOUNT           PIC X(64).
       01 WS-AMOUNT-STR           PIC X(32).

      *> VULNERABILITY: PIC 9(8)V99 silently overflows at 99999999.99
      *>   Adding to a near-max balance wraps to near zero with no error
       01 WS-AMOUNT               PIC 9(8)V99.
       01 WS-AMOUNT-DISP          PIC -Z(7)9.99.

       01 WS-UPDATE-FROM          PIC X(1000).
       01 WS-UPDATE-TO            PIC X(1000).
       01 WS-SELECT-BAL           PIC X(1000).
       01 WS-RESULT-2             PIC X(16000).

       01 WS-FROM-BAL             PIC X(512).
       01 WS-TO-BAL               PIC X(512).
       01 WS-JSON-OUT             PIC X(2048).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM READ-POST-BODY
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-TRANSFER-FIELDS
           PERFORM EXECUTE-DEBIT
           PERFORM EXECUTE-CREDIT
           PERFORM FETCH-NEW-BALANCES
           PERFORM BUILD-RESPONSE
           STOP RUN.

      *>
      *> VULNERABILITY: Amount comes from caller with no server-side
      *>   authentication. No session token checked. Anyone can submit
      *>   a transfer from any account to any account.
       EXTRACT-TRANSFER-FIELDS.
           MOVE "fromAccount" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-FROM-ACCOUNT

           MOVE "toAccount" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-TO-ACCOUNT

           MOVE "amount" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-AMOUNT-STR

      *>     VULNERABILITY: negative value accepted silently
      *>       amount=-500 debits TO-account and credits FROM-account
           MOVE FUNCTION NUMVAL(WS-AMOUNT-STR) TO WS-AMOUNT
           MOVE WS-AMOUNT TO WS-AMOUNT-DISP.

      *>
      *> VULNERABILITY: SQL injection on WS-FROM-ACCOUNT
      *>   Payload: fromAccount=1001' OR '1'='1
      *>   Debits ALL accounts simultaneously
       EXECUTE-DEBIT.
           STRING
               "UPDATE accounts SET balance = balance - "
               FUNCTION TRIM(WS-AMOUNT-STR) DELIMITED SIZE
               " WHERE id = '"
               FUNCTION TRIM(WS-FROM-ACCOUNT) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-UPDATE-FROM
           END-STRING
           CALL "sqlexec" USING BY REFERENCE WS-UPDATE-FROM
                                 BY REFERENCE WS-SQL-RESULT.

      *>
       EXECUTE-CREDIT.
           STRING
               "UPDATE accounts SET balance = balance + "
               FUNCTION TRIM(WS-AMOUNT-STR) DELIMITED SIZE
               " WHERE id = '"
               FUNCTION TRIM(WS-TO-ACCOUNT) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-UPDATE-TO
           END-STRING
           CALL "sqlexec" USING BY REFERENCE WS-UPDATE-TO
                                 BY REFERENCE WS-RESULT-2.

      *>
       FETCH-NEW-BALANCES.
           STRING
               "SELECT balance FROM accounts WHERE id = '"
               FUNCTION TRIM(WS-FROM-ACCOUNT) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-SELECT-BAL
           END-STRING
           CALL "sqlexec" USING BY REFERENCE WS-SELECT-BAL
                                 BY REFERENCE WS-SQL-RESULT

           MOVE "balance" TO WS-SQL-FIELD
           CALL "jsonget" USING BY REFERENCE WS-SQL-RESULT
                                 BY REFERENCE WS-SQL-FIELD
                                 BY REFERENCE WS-FROM-BAL

           STRING
               "SELECT balance FROM accounts WHERE id = '"
               FUNCTION TRIM(WS-TO-ACCOUNT) DELIMITED SIZE
               "'"
               DELIMITED SIZE
               INTO WS-SELECT-BAL
           END-STRING
           CALL "sqlexec" USING BY REFERENCE WS-SELECT-BAL
                                 BY REFERENCE WS-RESULT-2

           MOVE "balance" TO WS-SQL-FIELD
           CALL "jsonget" USING BY REFERENCE WS-RESULT-2
                                 BY REFERENCE WS-SQL-FIELD
                                 BY REFERENCE WS-TO-BAL.

      *>
       BUILD-RESPONSE.
           STRING
               '{"success": true,'
               ' "fromAccount": "'
               FUNCTION TRIM(WS-FROM-ACCOUNT) DELIMITED SIZE
               '", "toAccount": "'
               FUNCTION TRIM(WS-TO-ACCOUNT) DELIMITED SIZE
               '", "amount": "'
               FUNCTION TRIM(WS-AMOUNT-DISP) DELIMITED SIZE
               '", "fromBalance": "'
               FUNCTION TRIM(WS-FROM-BAL) DELIMITED SIZE
               '", "toBalance": "'
               FUNCTION TRIM(WS-TO-BAL) DELIMITED SIZE
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT
           END-STRING
           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
