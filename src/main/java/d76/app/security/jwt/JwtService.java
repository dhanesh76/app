package d76.app.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {

    private final String secret;
    private final Long tokenTTL;

    JwtService(@Value("${jwt.secret}") String secret,
               @Value("${jwt.tokenTTL}") Long tokenTTL
    ) {
        this.secret = secret;
        this.tokenTTL = tokenTTL;
    }

    SecretKey getKey(){
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateAccessToken(UserDetails principal){

        var  jit = UUID.randomUUID().toString();
        var role = principal
                .getAuthorities()
                .stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("");

        return  Jwts
                .builder()
                .id(jit)
                .subject(principal.getUsername())
                .signWith(getKey(), Jwts.SIG.HS256)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(tokenTTL)))
                .claim("role", role)
                .compact();
    }

    Claims extractClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    String extractUsername(String token){
        return extractClaims(token).getSubject();
    }

    Date extractExpiration(String token){
        return extractClaims(token).getExpiration();
    }

    boolean validateToken(UserDetails principal, String token){
            boolean isUsernameMatches = extractUsername(token).equals(principal.getUsername());
            boolean isTokenValid = (new Date()).before(extractExpiration(token));
            return isUsernameMatches && isTokenValid;
    }
}
