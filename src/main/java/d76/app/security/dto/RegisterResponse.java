package d76.app.security.dto;

import java.time.Instant;

public record RegisterResponse(String email, Instant createdAt){}
