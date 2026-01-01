package d76.app.security.oauth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import d76.app.auth.model.AuthProvider;
import d76.app.user.repo.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final UsersRepository usersRepository;
    private final ObjectMapper objectMapper;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        var oidcUser = super.loadUser(userRequest);
        String provider = userRequest.getClientRegistration().getRegistrationId();

        String email = oidcUser.getAttribute("email");
        if(email == null){
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            "email_missing",
                            constructPayload(provider, null),
                            null
                    ),
                    provider + " account has no accessible email"
            );
        }

        var user = usersRepository.findByEmail(email).orElseThrow(
                () -> new OAuth2AuthenticationException(
                        new OAuth2Error("user_not_registered",
                                constructPayload(provider, email),
                                null),
                        "No account exists with the email: " + email
                )
        );

        if (!user.getAuthProviders().contains(AuthProvider.GOOGLE)) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(
                            "auth_provider_not_linked",
                            constructPayload(provider, email),
                            null
                    ),
                    "The email address " + email +
                            " is not associated with Google sign-in. Do you want to link?"
            );
        }

        var authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();


        return new DefaultOidcUser(authorities, userRequest.getIdToken(), oidcUser.getUserInfo());
    }

    private String constructPayload(String provider, String email) {
        Map<String, Object> meta = new HashMap<>();
        meta.put("provider", provider);
        if (email != null)
            meta.put("email", email);

        try {
            return objectMapper.writeValueAsString(meta);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
