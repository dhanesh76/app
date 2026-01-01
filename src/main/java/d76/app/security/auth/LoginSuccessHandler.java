package d76.app.security.auth;

import d76.app.auth.dto.LoginSuccess;
import d76.app.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;

@NullMarked
@Component
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException {

        Object principal = authentication.getPrincipal();

        String username;
        String provider = "EMAIL";

        if (principal instanceof OidcUser oidcUser) {
            username = oidcUser.getEmail();
            provider = "GOOGLE";
        } else if (principal instanceof OAuth2User oauth2User) {
            username = oauth2User.getAttribute("email");
            provider = "GITHUB";
        } else if (principal instanceof UserDetails ud) {
            username = ud.getUsername();
        } else {
            throw new IllegalStateException("Unsupported principal type");
        }

        if (username == null || username.isBlank()) {
            throw new IllegalStateException("Authenticated user has no email");
        }

        var userDetails = userDetailsService.loadUserByUsername(username);
        String token = jwtService.generateAccessToken(userDetails);

        var loginResponse = LoginSuccess.builder()
                .status("LOGIN_SUCCESS")
                .username(username)
                .accessToken(token)
                .authProvider(provider)
                .issuedAt(Instant.now())
                .build();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), loginResponse);
    }
}
