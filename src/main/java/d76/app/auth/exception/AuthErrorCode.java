package d76.app.auth.exception;

import d76.app.core.exception.ErrorCode;
import org.springframework.http.HttpStatus;

public enum AuthErrorCode implements ErrorCode {

    // authentication
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "The provided credentials are invalid."),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "You do not have permission to access this resource."),

    // registration
    ROLE_NOT_FOUND(HttpStatus.NOT_FOUND, "The specified role does not exist."),
    USERNAME_TAKEN(HttpStatus.CONFLICT, "This username is already in use."),
    EMAIL_ALREADY_REGISTERED(HttpStatus.CONFLICT, "An account already exists with this email address."),

    // oauth
    USER_NOT_REGISTERED(HttpStatus.CONFLICT, "No account is associated with this email address."),
    EMAIL_REQUIRED(HttpStatus.BAD_REQUEST, "A valid email address is required."),

    // provider linking
    AUTH_PROVIDER_NOT_LINKED(HttpStatus.CONFLICT,
            "This email address is not linked to the selected authentication provider. " +
                    "Please sign in using a linked method or link this provider in your account settings.");

    private final HttpStatus status;
    private final String defaultMessage;

    AuthErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    @Override
    public HttpStatus getStatus() {
        return status;
    }

    @Override
    public String defaultMessage() {
        return defaultMessage;
    }
}
