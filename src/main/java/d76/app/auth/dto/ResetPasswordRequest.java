package d76.app.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.Length;

public record ResetPasswordRequest(
        @NotBlank String email,
        @Size(min = 5, max = 7) String otp,
        @Length(min = 8) String newPassword
) {
}
