      *> COBOLGoat - Intentionally Vulnerable COBOL Application
      *> interest-calc.cbl - Compound interest calculator with numeric vulnerabilities
      *>
      *> VULNERABILITIES:
      *>   1. Numeric overflow - PIC 9(8)V99 silently wraps on large values
      *>      Try: principal=99999999, rate=10, years=30
      *>   2. No input validation - negative rates and years accepted
      *>      Negative rate: interest reduces principal (silent wealth drain)
      *>      Zero years: returns principal unchanged (no error)
      *>      Negative years: undefined behavior / garbled output
      *>   3. Precision loss - fixed-point truncation in compound calculation
      *>      Each iteration truncates fractional cents, error compounds over time
      *>   4. No bounds checking on COMPUTE results

       IDENTIFICATION DIVISION.
       PROGRAM-ID. INTEREST-CALC.
       AUTHOR. COBOLGoat.

       ENVIRONMENT DIVISION.
       CONFIGURATION SECTION.

       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 WS-ARGC                 PIC 99.
       01 WS-ARG1                 PIC X(256).
       01 WS-ARG2                 PIC X(256).
       01 WS-ARG3                 PIC X(256).

       01 WS-PRINCIPAL-STR        PIC X(256).
       01 WS-RATE-STR             PIC X(256).
       01 WS-YEARS-STR            PIC X(256).

      *> VULNERABILITY: Numeric overflow - max value 99999999.99
      *> Exceeding this silently wraps to 0 and counts up again
       01 WS-PRINCIPAL            PIC 9(8)V99.
       01 WS-RATE                 PIC S9(5)V99.
       01 WS-YEARS                PIC S9(4).

      *> VULNERABILITY: Intermediate calculation also overflows silently
       01 WS-BALANCE              PIC 9(8)V99.
       01 WS-PREV-BALANCE         PIC 9(8)V99.
       01 WS-INTEREST             PIC 9(8)V99.
       01 WS-RATE-DECIMAL         PIC S9(3)V9(6).
       01 WS-YEAR-IDX             PIC S9(4).
       01 WS-OVERFLOW-DETECTED    PIC X VALUE "N".

       01 WS-PRINCIPAL-DISP       PIC Z(7)9.99.
       01 WS-RATE-DISP            PIC -Z(4)9.99.
       01 WS-BALANCE-DISP         PIC Z(7)9.99.

       01 WS-JSON-OUT             PIC X(512).
       01 WS-OVERFLOW-FLAG        PIC X(5) VALUE "false".

       PROCEDURE DIVISION.
       MAIN-PARA.
           ACCEPT WS-ARGC FROM ARGUMENT-NUMBER
           IF WS-ARGC < 3
               DISPLAY '{"error": "Usage: interest-calc <principal>'
                   ' <rate_percent> <years>"}'
               MOVE 1 TO RETURN-CODE
               STOP RUN
           END-IF

           ACCEPT WS-ARG1 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG2 FROM ARGUMENT-VALUE
           ACCEPT WS-ARG3 FROM ARGUMENT-VALUE

           MOVE FUNCTION TRIM(WS-ARG1) TO WS-PRINCIPAL-STR
           MOVE FUNCTION TRIM(WS-ARG2) TO WS-RATE-STR
           MOVE FUNCTION TRIM(WS-ARG3) TO WS-YEARS-STR

      *> VULNERABILITY: No input validation - all values accepted as-is
      *> Negative rates, zero years, huge principals all accepted silently
           MOVE FUNCTION NUMVAL(WS-PRINCIPAL-STR) TO WS-PRINCIPAL
           MOVE FUNCTION NUMVAL(WS-RATE-STR) TO WS-RATE
           MOVE FUNCTION NUMVAL(WS-YEARS-STR) TO WS-YEARS

           MOVE WS-PRINCIPAL TO WS-BALANCE

      *> VULNERABILITY: Precision loss in rate conversion
      *> Dividing by 100 truncates fractional representation
           COMPUTE WS-RATE-DECIMAL = WS-RATE / 100

           PERFORM VARYING WS-YEAR-IDX FROM 1 BY 1
               UNTIL WS-YEAR-IDX > WS-YEARS

               MOVE WS-BALANCE TO WS-PREV-BALANCE

      *> VULNERABILITY: Intermediate result truncated at each step
      *> Each truncation introduces a small error that compounds over time
      *> At 30 years with 10%, the accumulated error can be several dollars
               COMPUTE WS-INTEREST ROUNDED =
                   WS-BALANCE * WS-RATE-DECIMAL

      *> VULNERABILITY: Overflow - if WS-BALANCE approaches 99999999.99
      *> adding WS-INTEREST silently wraps to near-zero
               ADD WS-INTEREST TO WS-BALANCE

      *> Detect overflow: new balance should always be >= previous
      *> (for positive rates) - if smaller, overflow occurred
               IF WS-RATE > 0 AND WS-BALANCE < WS-PREV-BALANCE
                   MOVE "Y" TO WS-OVERFLOW-DETECTED
                   MOVE "true" TO WS-OVERFLOW-FLAG
               END-IF
           END-PERFORM

           MOVE WS-PRINCIPAL TO WS-PRINCIPAL-DISP
           MOVE WS-RATE TO WS-RATE-DISP
           MOVE WS-BALANCE TO WS-BALANCE-DISP

           STRING '{"principal": "'
               FUNCTION TRIM(WS-PRINCIPAL-DISP)
               '", "rate": "'
               FUNCTION TRIM(WS-RATE-DISP)
               '", "years": "'
               FUNCTION TRIM(WS-YEARS-STR)
               '", "finalBalance": "'
               FUNCTION TRIM(WS-BALANCE-DISP)
               '", "overflow": '
               FUNCTION TRIM(WS-OVERFLOW-FLAG)
               '}'
               DELIMITED SIZE
               INTO WS-JSON-OUT

           DISPLAY FUNCTION TRIM(WS-JSON-OUT)
           STOP RUN.
