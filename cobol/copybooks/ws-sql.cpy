      *> COBOLBank - SQL WORKING-STORAGE copybook
      *> COPY "ws-sql.cpy" in WORKING-STORAGE SECTION

      *> VULNERABILITY: WS-SQL-QUERY is built by STRING concatenation;
      *>   no parameter binding, no escaping. Callers inject directly here.
       01 WS-SQL-QUERY            PIC X(1000).
       01 WS-SQL-RESULT           PIC X(16000).

      *> Convenience pointer into the result for COBOL programs that
      *> need to pull individual columns back out via json-get
       01 WS-SQL-FIELD            PIC X(64).
       01 WS-SQL-VALUE            PIC X(512).
