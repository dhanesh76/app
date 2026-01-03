package d76.app.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.core.exception.ApiErrorResponse;
import d76.app.core.exception.BusinessException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;

@Component
@NullMarked
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String header = request.getHeader("Authorization");
            if (header != null &&
                    header.startsWith("Bearer ") &&
                    SecurityContextHolder.getContext().getAuthentication() == null) {

                String token = header.substring("Bearer ".length()).trim();
                String username = jwtService.extractUserName(token);

                if (username != null && !username.isBlank()) {
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    jwtService.assertAccessTokenValid(userDetails, token);

                    var authToken = UsernamePasswordAuthenticationToken.authenticated(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder
                            .getContext()
                            .setAuthentication(authToken);

                }
            }

            filterChain.doFilter(request, response);
        } catch (BusinessException e) {
            var errorCode = e.getErrorCode();

            response.setStatus(errorCode.getStatus().value());
            response.setContentType("application/json");

            var errorResponse = ApiErrorResponse
                    .builder()
                    .errorCode(errorCode.getCode())
                    .statusCode(HttpStatus.UNAUTHORIZED.value())
                    .path(request.getRequestURI())
                    .message(e.getMessage())
                    .timestamp(Instant.now())
                    .build();

            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        }
    }
}
