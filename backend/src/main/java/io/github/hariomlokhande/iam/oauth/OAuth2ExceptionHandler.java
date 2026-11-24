package io.github.hariomlokhande.iam.oauth;

import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Renders OAuth2 protocol errors in the format the specification defines, so client
 * libraries can parse them. It is scoped to the OAuth2 endpoints; everything else
 * keeps the platform error shape.
 */
@RestControllerAdvice(assignableTypes = OAuth2Controller.class)
public class OAuth2ExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2ExceptionHandler.class);

    @ExceptionHandler(OAuth2Exception.class)
    public ResponseEntity<Map<String, String>> handle(OAuth2Exception exception) {
        log.debug("OAuth2 error {}: {}", exception.error(), exception.getMessage());

        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", exception.error());
        body.put("error_description", exception.getMessage());

        ResponseEntity.BodyBuilder response = ResponseEntity.status(exception.status())
                .header(HttpHeaders.CACHE_CONTROL, "no-store");
        if (OAuth2Exception.INVALID_CLIENT.equals(exception.error())) {
            // A 401 without a challenge header is not a well-formed rejection.
            response.header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"oauth2\"");
        }
        return response.body(body);
    }
}
