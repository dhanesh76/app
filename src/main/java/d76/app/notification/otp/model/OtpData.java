package d76.app.notification.otp.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record OtpData(
        @NotBlank String otp,
        @NotNull OtpPurpose purpose,
        @NotNull Instant issuedAt
) {
}
