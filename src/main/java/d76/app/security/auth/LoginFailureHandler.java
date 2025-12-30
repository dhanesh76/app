package d76.app.security.auth;

import d76.app.core.exception.ApiErrorResponse;
import d76.app.auth.exception.AuthErrorCode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;

@NullMarked
@Component
@RequiredArgsConstructor
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse res, AuthenticationException ex) throws IOException {

        if (ex instanceof OAuth2AuthenticationException oae) {
            var oaeError = oae.getError();

            String provider =  "";
            String desc = oaeError.getDescription();
            if(desc != null && oaeError.getDescription().startsWith("provider:"))
                provider = desc.substring("provider:".length());

            switch (oaeError.getErrorCode()) {
                case "user_not_registered" -> {

                    var statuscode = HttpStatus.CONFLICT.value();

                    res.setStatus(statuscode);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.USER_NOT_REGISTERED.name())
                            .statusCode(statuscode)
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .authProvider(provider.toUpperCase())
                            .build();
                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
                case "email_missing" -> {
                    var statuscode = HttpStatus.BAD_REQUEST.value();

                    res.setStatus(statuscode);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.EMAIL_REQUIRED.name())
                            .statusCode(statuscode)
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .authProvider(provider.toUpperCase())
                            .build();

                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
                case "auth_provider_not_linked" -> {
                    var statuscode = HttpStatus.CONFLICT.value();

                    res.setStatus(statuscode);
                    res.setContentType("application/json");

                    ApiErrorResponse response = ApiErrorResponse
                            .builder()
                            .errorCode(AuthErrorCode.AUTH_PROVIDER_NOT_LINKED.name())
                            .statusCode(statuscode)
                            .message(ex.getMessage())
                            .timestamp(Instant.now())
                            .path(request.getRequestURI())
                            .authProvider(provider)
                            .build();

                    res.getWriter().write(objectMapper.writeValueAsString(response));
                    return;
                }
            }
        };

        var errorCode = AuthErrorCode.INVALID_CREDENTIALS;
        ApiErrorResponse errorResponse = ApiErrorResponse.builder()
                .statusCode(errorCode.getStatus().value())
                .errorCode(errorCode.getCode())
                .message(errorCode.defaultMessage())
                .path(request.getRequestURI())
                .timestamp(Instant.now())
                .build();

        res.setStatus(errorCode.getStatus().value());
        res.setContentType("application/json");
        res.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
