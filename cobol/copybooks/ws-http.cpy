      *> COBOLBank - HTTP response WORKING-STORAGE copybook
      *> COPY "ws-http.cpy" in WORKING-STORAGE SECTION

       01 HTTP-RESPONSE.
          05 HTTP-STATUS          PIC X(3) VALUE "200".
          05 HTTP-CONTENT-TYPE    PIC X(64)
             VALUE "application/json".

       01 HTTP-HEADERS-WRITTEN    PIC X VALUE "N".
          88 HEADERS-SENT         VALUE "Y".

      *> Reusable error message field
       01 HTTP-ERROR-MSG          PIC X(256).
