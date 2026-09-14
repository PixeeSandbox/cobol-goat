      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> account-lookup.cbl - Account lookup with IDOR and SQL injection
      *>
      *> VULNERABILITIES:
      *>   1. IDOR - No authorization check that user owns the account
      *>   2. SQL Injection - numeric field without quotes, direct concatenation
      *>   3. PII exposure - SSN returned in every response

       IDENTIFICATION DIVISION.
       PROGRAM-ID. ACCOUNT-LOOKUP.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).

       01 WS-ACCOUNT-ID           PIC X(256).
       01 WS-USER-ID              PIC X(256).

      *> VULNERABILITY: SQL Injection - numeric field, no quotes, no sanitization
       01 WS-QUERY                PIC X(512).

      *> Hardcoded account data (simulating DB records)
       01 WS-ACCT-TABLE.
           05 WS-ACCT OCCURS 3 TIMES.
               10 WS-ACCT-ID      PIC X(10).
               10 WS-ACCT-OWNER   PIC X(30).
               10 WS-ACCT-BAL     PIC X(15).
               10 WS-ACCT-SSN     PIC X(15).

       01 WS-IDX                  PIC 9.
       01 WS-FOUND                PIC X VALUE "N".
       01 WS-JSON-OUT             PIC X(1024).

       PROCEDURE DIVISION.
       MAIN-PARA.
           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 1
               DISPLAY '{"error": "Usage: account-lookup <account_id>'
                   ' [user_id]"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           MOVE FUNCTION TRIM(WS-ARG1) TO WS-ACCOUNT-ID

           IF WS-ARGC >= 2
               ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
               MOVE FUNCTION TRIM(WS-ARG2) TO WS-USER-ID
           ELSE
               MOVE "anonymous" TO WS-USER-ID
           END-IF

      *> VULNERABILITY: IDOR - user_id is accepted but never validated
      *> No check that WS-USER-ID owns account WS-ACCOUNT-ID
      *> Any user can look up any account by simply passing the account ID

      *> VULNERABILITY: SQL Injection - numeric ID concatenated without quotes
      *> Attacker can pass: 1001 OR 1=1 -- to return all accounts
           STRING "SELECT * FROM ACCOUNTS WHERE ID = "
               FUNCTION TRIM(WS-ACCOUNT-ID)
               DELIMITED SIZE
               INTO WS-QUERY
           END-STRING

      *> Load hardcoded account data
           MOVE "1001" TO WS-ACCT-ID(1)
           MOVE "Alice Johnson" TO WS-ACCT-OWNER(1)
           MOVE "15432.50" TO WS-ACCT-BAL(1)
           MOVE "123-45-6789" TO WS-ACCT-SSN(1)

           MOVE "1002" TO WS-ACCT-ID(2)
           MOVE "Bob Smith" TO WS-ACCT-OWNER(2)
           MOVE "2100.00" TO WS-ACCT-BAL(2)
           MOVE "987-65-4321" TO WS-ACCT-SSN(2)

           MOVE "1003" TO WS-ACCT-ID(3)
           MOVE "Admin Account" TO WS-ACCT-OWNER(3)
           MOVE "999999.99" TO WS-ACCT-BAL(3)
           MOVE "000-00-0000" TO WS-ACCT-SSN(3)

           MOVE "N" TO WS-FOUND

           PERFORM VARYING WS-IDX FROM 1 BY 1 UNTIL WS-IDX > 3
               IF FUNCTION TRIM(WS-ACCT-ID(WS-IDX)) =
                   FUNCTION TRIM(WS-ACCOUNT-ID)
                   MOVE "Y" TO WS-FOUND

      *> VULNERABILITY: PII (SSN) returned without any authorization check
                   STRING '{"accountId": "'
                       FUNCTION TRIM(WS-ACCT-ID(WS-IDX))
                       '", "owner": "'
                       FUNCTION TRIM(WS-ACCT-OWNER(WS-IDX))
                       '", "balance": "'
                       FUNCTION TRIM(WS-ACCT-BAL(WS-IDX))
                       '", "ssn": "'
                       FUNCTION TRIM(WS-ACCT-SSN(WS-IDX))
                       '", "query": "'
                       FUNCTION TRIM(WS-QUERY)
                       '"}'
                       DELIMITED SIZE
                       INTO WS-JSON-OUT
                   DISPLAY FUNCTION TRIM(WS-JSON-OUT)
               END-IF
           END-PERFORM

           IF WS-FOUND = "N"
               STRING '{"error": "Account not found", "accountId": "'
                   FUNCTION TRIM(WS-ACCOUNT-ID)
                   '", "query": "'
                   FUNCTION TRIM(WS-QUERY)
                   '"}'
                   DELIMITED SIZE
                   INTO WS-JSON-OUT
               DISPLAY FUNCTION TRIM(WS-JSON-OUT)
               MOVE 1 TO RETURN-CODE
           END-IF

           STOP RUN.
