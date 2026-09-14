      *> COBOLBank - HTTP response procedure copybook
      *> COPY "proc-http.cpy" in PROCEDURE DIVISION
      *> Requires ws-http.cpy in WORKING-STORAGE

       WRITE-JSON-HEADER.
           DISPLAY "Content-Type: application/json"
           DISPLAY "Access-Control-Allow-Origin: *"
           DISPLAY x'0a' WITH NO ADVANCING
           MOVE "Y" TO HTTP-HEADERS-WRITTEN.

      *> WRITE-JSON-ERROR: set HTTP-ERROR-MSG before calling.
      *> Writes {"error": "..."} and sets RETURN-CODE to 1.
       WRITE-JSON-ERROR.
           IF NOT HEADERS-SENT
               PERFORM WRITE-JSON-HEADER
           END-IF
           DISPLAY '{"error": "' WITH NO ADVANCING
           DISPLAY FUNCTION TRIM(HTTP-ERROR-MSG) WITH NO ADVANCING
           DISPLAY '"}'
           MOVE 1 TO RETURN-CODE.
