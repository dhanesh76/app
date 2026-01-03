package d76.app.core.notification.otp.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record OtpData(
        @NotBlank String otp,
        @NotNull Long ttl,
        @NotNull OtpPurpose purpose,
        @NotNull Instant issuedAt
) {
}
