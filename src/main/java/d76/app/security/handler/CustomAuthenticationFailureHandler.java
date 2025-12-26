package d76.app.security.handler;

import d76.app.exception.ApiErrorResponse;
import d76.app.security.exception.AuthErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;

@NullMarked
@Component
@RequiredArgsConstructor
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse res, AuthenticationException ex) throws IOException {
        if (ex instanceof OAuth2AuthenticationException oae) {
            switch (oae.getError().getErrorCode()) {
                case "user_not_registered" -> {
                    res.setStatus(409);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.USER_NOT_REGISTERED.name())
                            .statusCode(HttpStatus.CONFLICT.value())
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .build();
                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
                case "email_missing" -> {
                    res.setStatus(400);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.EMAIL_REQUIRED.name())
                            .statusCode(HttpStatus.BAD_REQUEST.value())
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .build();
                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
                case "auth_provider_not_linked" -> {
                    res.setStatus(409);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.AUTH_PROVIDER_NOT_LINKED.name())
                            .statusCode(HttpStatus.CONFLICT.value())
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .build();
                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
            }
        }
        res.setStatus(401);
        res.setContentType("application/json");
        res.getWriter().write(objectMapper.writeValueAsString(
                Map.of("error", "authentication_failed",
                        "message", ex.getMessage()
                )
        ));
    }
}
