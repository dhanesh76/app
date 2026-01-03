package d76.app.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record RegisterResponse(
        @NotBlank String email,
        @NotBlank String provider,
        @NotNull Instant createdAt
) {
}
