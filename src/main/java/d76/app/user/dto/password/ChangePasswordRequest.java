package d76.app.user.dto.password;

import jakarta.validation.constraints.NotBlank;

public record ChangePasswordRequest(
        @NotBlank String reauthenticateToken,
        @NotBlank String newPassword
) {
}
