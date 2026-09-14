      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> search.cbl - Product search with SQL injection vulnerability
      *>
      *> VULNERABILITIES:
      *>   1. SQL Injection - search term embedded in LIKE clause without sanitization
      *>      Attacker can escape with: ' OR '1'='1
      *>      Or terminate with: %' UNION SELECT username,password FROM users --

       IDENTIFICATION DIVISION.
       PROGRAM-ID. SEARCH.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).

       01 WS-SEARCH-TERM          PIC X(256).

      *> VULNERABILITY: SQL Injection - LIKE clause with unsanitized user input
       01 WS-QUERY                PIC X(512).

      *> Hardcoded product catalog
       01 WS-PRODUCT-TABLE.
           05 WS-PRODUCT OCCURS 5 TIMES.
               10 WS-PROD-NAME    PIC X(40).

       01 WS-IDX                  PIC 9.
       01 WS-MATCH-COUNT          PIC 9 VALUE 0.
       01 WS-RESULTS              PIC X(512).
       01 WS-JSON-OUT             PIC X(1024).
       01 WS-SEARCH-UPPER         PIC X(256).
       01 WS-PROD-UPPER           PIC X(40).
       01 WS-FIRST-MATCH          PIC X VALUE "Y".

       PROCEDURE DIVISION.
       MAIN-PARA.
           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 1
               DISPLAY '{"error": "Usage: search <search_term>"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           MOVE FUNCTION TRIM(WS-ARG1) TO WS-SEARCH-TERM

      *> VULNERABILITY: SQL Injection
      *> User input placed inside LIKE '%...%' without any escaping or validation
      *> Attacker input: %' UNION SELECT table_name,NULL FROM information_schema.tables --
           STRING "SELECT * FROM PRODUCTS WHERE NAME LIKE '%"
               FUNCTION TRIM(WS-SEARCH-TERM)
               "%'"
               DELIMITED SIZE
               INTO WS-QUERY
           END-STRING

      *> Load product catalog
           MOVE "COBOL Manual"           TO WS-PROD-NAME(1)
           MOVE "Mainframe Guide"        TO WS-PROD-NAME(2)
           MOVE "Legacy System Handbook" TO WS-PROD-NAME(3)
           MOVE "VSAM Reference"         TO WS-PROD-NAME(4)
           MOVE "JCL Cookbook"           TO WS-PROD-NAME(5)

      *> Simple case-insensitive substring match
           MOVE FUNCTION UPPER-CASE(FUNCTION TRIM(WS-SEARCH-TERM))
               TO WS-SEARCH-UPPER

           MOVE "[" TO WS-RESULTS
           MOVE "Y" TO WS-FIRST-MATCH
           MOVE 0 TO WS-MATCH-COUNT

           PERFORM VARYING WS-IDX FROM 1 BY 1 UNTIL WS-IDX > 5
               MOVE FUNCTION UPPER-CASE(
                   FUNCTION TRIM(WS-PROD-NAME(WS-IDX)))
                   TO WS-PROD-UPPER

               IF FUNCTION TRIM(WS-SEARCH-UPPER) = SPACES
                   OR WS-PROD-UPPER(1:FUNCTION LENGTH(
                       FUNCTION TRIM(WS-SEARCH-UPPER)))
                       = FUNCTION TRIM(WS-SEARCH-UPPER)
                   OR WS-PROD-UPPER = FUNCTION TRIM(WS-SEARCH-UPPER)

                   IF WS-FIRST-MATCH = "N"
                       STRING FUNCTION TRIM(WS-RESULTS)
                           ", "
                           DELIMITED SIZE
                           INTO WS-RESULTS
                   END-IF

                   STRING FUNCTION TRIM(WS-RESULTS)
                       '"'
                       FUNCTION TRIM(WS-PROD-NAME(WS-IDX))
                       '"'
                       DELIMITED SIZE
                       INTO WS-RESULTS

                   MOVE "N" TO WS-FIRST-MATCH
                   ADD 1 TO WS-MATCH-COUNT
               END-IF
           END-PERFORM

           STRING FUNCTION TRIM(WS-RESULTS) "]"
               DELIMITED SIZE INTO WS-RESULTS

           STRING '{"results": '
               FUNCTION TRIM(WS-RESULTS)
               ', "count": '
               WS-MATCH-COUNT
               ', "query": "'
               FUNCTION TRIM(WS-QUERY)
               '"}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
