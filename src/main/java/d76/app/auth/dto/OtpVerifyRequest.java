package d76.app.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record OtpVerifyRequest(
        @Email String email,
        @Min(5) @Max(7) String otp
) {
}
