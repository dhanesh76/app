package d76.app.auth.dto;


import d76.app.notification.otp.model.OtpPurpose;
import jakarta.validation.constraints.Email;
import lombok.NonNull;

public record OtpRequest(
        @Email String email,
        @NonNull OtpPurpose purpose
) {
}
