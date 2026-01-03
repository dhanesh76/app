package d76.app.user.dto.password;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record VerifyPasswordResponse(
        @NotBlank String reauthenticateToken,
        @NotNull Instant issuedAt
) {
}
