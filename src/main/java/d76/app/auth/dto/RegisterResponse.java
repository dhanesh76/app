package d76.app.auth.dto;

import java.time.Instant;

public record RegisterResponse(String email, Instant createdAt, String provider){}
