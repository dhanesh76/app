package d76.app.core.notification.otp.exception;

import d76.app.core.exception.ErrorCode;
import org.springframework.http.HttpStatus;

public enum OtpErrorCode implements ErrorCode {
    OTP_EXPIRED(HttpStatus.BAD_REQUEST, "The OTP has expired. Please request a new code."),
    INVALID_OTP(HttpStatus.BAD_REQUEST, "The OTP is incorrect. Please check the code you entered.");

    private final String defaultMessage;
    private final HttpStatus status;

    OtpErrorCode(HttpStatus status, String defaultMessage) {
        this.defaultMessage = defaultMessage;
        this.status = status;
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
