package d76.app.auth.dto;

import java.time.Instant;

public record TempRegisterResponse(String email, String message, Instant issuedAt) {
}
