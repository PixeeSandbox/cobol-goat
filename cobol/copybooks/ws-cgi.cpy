      *> COBOLBank - CGI WORKING-STORAGE copybook
      *> COPY "ws-cgi.cpy" in WORKING-STORAGE SECTION

       01 CGI-VARS.
          05 CGI-REQUEST-METHOD   PIC X(8).
             88 CGI-IS-GET        VALUE "GET".
             88 CGI-IS-POST       VALUE "POST".
          05 CGI-QUERY-STRING     PIC X(4096).
          05 CGI-CONTENT-LENGTH-S PIC X(16).
          05 CGI-CONTENT-TYPE     PIC X(128).
          05 CGI-HTTP-COOKIE      PIC X(4096).
          05 CGI-SERVER-NAME      PIC X(128).
          05 CGI-PATH-INFO        PIC X(256).

       01 CGI-POST-BODY           PIC X(4096).
       01 CGI-BODY-LEN            PIC 9(6) VALUE ZERO.

      *> Scratch fields for parameter extraction
       01 CGI-PARAM-NAME          PIC X(64).
       01 CGI-PARAM-VALUE         PIC X(1024).

      *> JSON field extraction
       01 JSON-FIELD-NAME         PIC X(64).
       01 JSON-FIELD-VALUE        PIC X(512).
