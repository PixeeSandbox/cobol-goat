      *> COBOLBank - CGI procedure copybook
      *> COPY "proc-cgi.cpy" in PROCEDURE DIVISION
      *> Requires ws-cgi.cpy in WORKING-STORAGE

       READ-CGI-VARS.
           ACCEPT CGI-REQUEST-METHOD   FROM ENVIRONMENT "REQUEST_METHOD"
           ACCEPT CGI-QUERY-STRING     FROM ENVIRONMENT "QUERY_STRING"
           ACCEPT CGI-CONTENT-LENGTH-S FROM ENVIRONMENT "CONTENT_LENGTH"
           ACCEPT CGI-CONTENT-TYPE     FROM ENVIRONMENT "CONTENT_TYPE"
           ACCEPT CGI-HTTP-COOKIE      FROM ENVIRONMENT "HTTP_COOKIE"
           ACCEPT CGI-SERVER-NAME      FROM ENVIRONMENT "SERVER_NAME"
           ACCEPT CGI-PATH-INFO        FROM ENVIRONMENT "PATH_INFO".

       READ-POST-BODY.
           IF CGI-IS-POST
               ACCEPT CGI-POST-BODY
           END-IF.

      *> GET-QUERY-PARAM: set CGI-PARAM-NAME before calling.
      *> Result lands in CGI-PARAM-VALUE.
       GET-QUERY-PARAM.
           CALL "urlparam" USING BY REFERENCE CGI-QUERY-STRING
                                 BY REFERENCE CGI-PARAM-NAME
                                 BY REFERENCE CGI-PARAM-VALUE.

      *> GET-JSON-FIELD: set JSON-FIELD-NAME before calling.
      *> Source JSON is CGI-POST-BODY. Result lands in JSON-FIELD-VALUE.
       GET-JSON-FIELD.
           CALL "jsonget" USING BY REFERENCE CGI-POST-BODY
                                BY REFERENCE JSON-FIELD-NAME
                                BY REFERENCE JSON-FIELD-VALUE.
