package d76.app.oauth.dto;

import jakarta.validation.constraints.NotBlank;

public record SocialLinkRequest(@NotBlank String actionToken) {
}
