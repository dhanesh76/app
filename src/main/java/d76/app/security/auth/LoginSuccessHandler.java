package d76.app.security.auth;

import d76.app.security.jwt.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Objects;

@NullMarked
@Component
@RequiredArgsConstructor
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String token = jwtService.generateAccessToken((UserDetails) Objects.requireNonNull(authentication.getPrincipal()));

        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json");
        response.getWriter().write("""
                {
                    "status": "LOGIN_SUCCESS",
                    "username":"%s",
                    "accessToken:""%s"
                }
                """.formatted(authentication.getName(), token)
        );
    }
}
