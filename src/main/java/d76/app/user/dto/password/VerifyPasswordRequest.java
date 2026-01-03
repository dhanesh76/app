package d76.app.user.dto.password;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

public record VerifyPasswordRequest(
        @NotBlank @Length(min = 8) String password
) {
}
