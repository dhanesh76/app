package d76.app.security.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.auth.model.AuthProvider;
import d76.app.user.entity.Users;
import d76.app.user.repo.UsersRepository;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final WebClient webClient;
    private final UsersRepository usersRepository;
    private final ObjectMapper objectMapper;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        var delegate = new DefaultOAuth2UserService();
        var oAuth2User = delegate.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();

        String email = fetchPrimaryEmail(userRequest, oAuth2User);

        if (email == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            "email_missing",
                            constructPayload(provider, null),
                            null
                    ),
                    provider + " account has no accessible email"
            );
        }

        Users user = usersRepository.findByEmail(email).orElseThrow(() ->
                new OAuth2AuthenticationException(
                        new OAuth2Error(
                                "user_not_registered",
                                constructPayload(provider, email),
                                null
                        ),
                        "No user exists with email: " + email
                )
        );

        if (!user.getAuthProviders().contains(AuthProvider.GITHUB)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("auth_provider_not_linked",
                            constructPayload(provider, email), null),
                    "The email address " + email +
                            " is not associated with Github sign-in. Do you want to link?");
        }

        var authorities = user.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.getName()))
                .toList();

        var attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("email", email);

        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    private String constructPayload(String provider, String email) {
        Map<String, Object> meta = new HashMap<>();
        meta.put("authProvider", provider);
        if (email != null)
            meta.put("email", email);

        try {
            return objectMapper.writeValueAsString(meta);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Nullable
    private String fetchPrimaryEmail(OAuth2UserRequest request, OAuth2User oAuth2User) {

        String email = oAuth2User.getAttribute("email");
        if (email != null) return email;

        String token = request.getAccessToken().getTokenValue();

        var emails = webClient
                .get()
                .uri("https://api.github.com/user/emails")
                .headers(h -> h.setBearerAuth(token))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<@NonNull List<Map<String, Object>>>() {
                })
                .block();

        return emails == null ? null : emails.stream()
                .filter(e -> Boolean.TRUE.equals(e.get("primary")))
                .filter(e -> Boolean.TRUE.equals(e.get("verified")))
                .map(e -> (String) e.get("email"))
                .findFirst()
                .orElse(null);
    }
}
