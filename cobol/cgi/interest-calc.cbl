      *> COBOLBank - Compound interest calculator CGI endpoint
      *>
      *> VULNERABILITIES:
      *>   1. Numeric overflow - PIC 9(8)V99 silently wraps at 99999999.99
      *>      Try: principal=99999999, rate=10, years=5 → wraps near zero
      *>   2. No input validation - negative rates, zero years all accepted
      *>      Negative rate silently drains the principal each year
      *>   3. Precision loss - fixed-point truncation at each iteration
      *>      Each year's rounding error compounds; 30-year error: several dollars
      *>   4. COMPUTE silently discards overflow bits (no ON SIZE ERROR used)

       IDENTIFICATION DIVISION.
       PROGRAM-ID. INTEREST-CALC.
       AUTHOR. COBOLBank Security Training.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.

       COPY "ws-cgi.cpy".
       COPY "ws-http.cpy".
       COPY "ws-sql.cpy".

      *> Raw string inputs (kept for output - avoids garbled numeric display)
       01 WS-PRINCIPAL-STR        PIC X(32).
       01 WS-RATE-STR             PIC X(32).
       01 WS-YEARS-STR            PIC X(16).

      *> VULNERABILITY: PIC 9(8)V99 holds max 99999999.99
      *>   Exceeding this during COMPUTE wraps silently to near-zero
      *>   Real COBOL/CICS systems have caused million-dollar errors this way
       01 WS-PRINCIPAL            PIC 9(8)V99.
       01 WS-RATE                 PIC S9(5)V99.
       01 WS-YEARS                PIC S9(4).

      *> VULNERABILITY: Intermediate results overflow here too
       01 WS-BALANCE              PIC 9(8)V99.
       01 WS-PREV-BALANCE         PIC 9(8)V99.
       01 WS-INTEREST             PIC 9(8)V99.
       01 WS-RATE-DECIMAL         PIC S9(3)V9(6).
       01 WS-YEAR-IDX             PIC S9(4).

       01 WS-OVERFLOW-DETECTED    PIC X VALUE "N".
       01 WS-OVERFLOW-FLAG        PIC X(5) VALUE "false".

      *> Display fields with editing characters
       01 WS-PRINCIPAL-DISP       PIC Z(7)9.99.
       01 WS-RATE-DISP            PIC -Z(4)9.99.
       01 WS-BALANCE-DISP         PIC Z(7)9.99.

       01 WS-JSON-OUT             PIC X(512).

       PROCEDURE DIVISION.

       MAIN-PARA.
           PERFORM READ-CGI-VARS
           PERFORM READ-POST-BODY
           PERFORM WRITE-JSON-HEADER

           PERFORM EXTRACT-INPUTS
           PERFORM PARSE-NUMERIC-INPUTS
           PERFORM RUN-CALCULATION
           PERFORM BUILD-RESPONSE

           STOP RUN.

      *>
       EXTRACT-INPUTS.
           MOVE "principal" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-PRINCIPAL-STR

           MOVE "rate" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-RATE-STR

           MOVE "years" TO JSON-FIELD-NAME
           PERFORM GET-JSON-FIELD
           MOVE FUNCTION TRIM(JSON-FIELD-VALUE) TO WS-YEARS-STR.

      *>
      *> VULNERABILITY: FUNCTION NUMVAL accepts any numeric string,
      *>   including negatives and huge values, with no bounds checking
       PARSE-NUMERIC-INPUTS.
           MOVE FUNCTION NUMVAL(WS-PRINCIPAL-STR) TO WS-PRINCIPAL
           MOVE FUNCTION NUMVAL(WS-RATE-STR)      TO WS-RATE
           MOVE FUNCTION NUMVAL(WS-YEARS-STR)     TO WS-YEARS.

      *>
       RUN-CALCULATION.
           MOVE WS-PRINCIPAL TO WS-BALANCE
           MOVE "false"      TO WS-OVERFLOW-FLAG
           MOVE "N"          TO WS-OVERFLOW-DETECTED

      *>     VULNERABILITY: Dividing by 100 truncates fractional precision
           COMPUTE WS-RATE-DECIMAL = WS-RATE / 100

           PERFORM VARYING WS-YEAR-IDX FROM 1 BY 1
               UNTIL WS-YEAR-IDX > WS-YEARS

               MOVE WS-BALANCE TO WS-PREV-BALANCE

      *>         VULNERABILITY: No ON SIZE ERROR clause - overflow is silent
      *>         ROUNDED alone does not prevent wrap-around
               COMPUTE WS-INTEREST ROUNDED =
                   WS-BALANCE * WS-RATE-DECIMAL

      *>         VULNERABILITY: This ADD can silently wrap WS-BALANCE to zero
               ADD WS-INTEREST TO WS-BALANCE

      *>         Heuristic overflow detection (positive rates only)
               IF WS-RATE > 0 AND WS-BALANCE < WS-PREV-BALANCE
                   MOVE "Y"    TO WS-OVERFLOW-DETECTED
                   MOVE "true" TO WS-OVERFLOW-FLAG
               END-IF

           END-PERFORM.

      *>
       BUILD-RESPONSE.
           MOVE WS-PRINCIPAL TO WS-PRINCIPAL-DISP
           MOVE WS-RATE      TO WS-RATE-DISP
           MOVE WS-BALANCE   TO WS-BALANCE-DISP

           STRING
               '{"principal": "'
               FUNCTION TRIM(WS-PRINCIPAL-DISP) DELIMITED SIZE
               '", "rate": "'
               FUNCTION TRIM(WS-RATE-DISP) DELIMITED SIZE
               '", "years": "'
               FUNCTION TRIM(WS-YEARS-STR) DELIMITED SIZE
               '", "finalBalance": "'
               FUNCTION TRIM(WS-BALANCE-DISP) DELIMITED SIZE
               '", "overflow": '
               FUNCTION TRIM(WS-OVERFLOW-FLAG) DELIMITED SIZE
               '}'
               DELIMITED SIZE INTO WS-JSON-OUT
           END-STRING

           DISPLAY FUNCTION TRIM(WS-JSON-OUT).

       COPY "proc-http.cpy".
       COPY "proc-cgi.cpy".
