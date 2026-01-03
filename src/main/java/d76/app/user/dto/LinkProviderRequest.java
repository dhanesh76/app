package d76.app.user.dto;

import jakarta.validation.constraints.NotBlank;

public record LinkProviderRequest(
        @NotBlank String actionToken
) {
}
