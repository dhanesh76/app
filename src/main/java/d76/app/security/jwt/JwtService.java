package d76.app.security.jwt;

import d76.app.security.jwt.model.JwtPurpose;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.xml.crypto.Data;
import java.security.spec.PKCS8EncodedKeySpec;
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

    private SecretKey getKey(){
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

    boolean validateAccessToken(UserDetails principal, String token){
            boolean isUsernameMatches = extractUsername(token).equals(principal.getUsername());
            boolean notExpired = (new Date()).before(extractExpiration(token));

        return isUsernameMatches && notExpired;
    }

    public String generateActionToken(String email, JwtPurpose purpose, String provider){

        String jti = UUID.randomUUID().toString();
        return Jwts
                .builder()
                .id(jti)
                .subject(email)
                .claim("purpose", purpose.name())
                .claim("provider", provider)
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(300))) //valid for 5 mins
                .signWith(getKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean validateActionToken(String token, JwtPurpose purpose){
        var claims = extractClaims(token);

        var purposeMatches = purpose.name().equals(claims.get("purpose", String.class));
        var notExpired = new Date().before(extractExpiration(token));

        return purposeMatches && notExpired;
    }

    public Claims extractClaims(String token){
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
}