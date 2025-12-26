package d76.app.oauth;

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

@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final UsersRepository usersRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        var oidcUser = super.loadUser(userRequest);

        String email = oidcUser.getAttribute("email");
        if(email == null){
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_missing"),
                    "Google account has no accessible email"
            );
        }

        var user = usersRepository.findByEmail(email).orElseThrow(
                () -> new OAuth2AuthenticationException(
                        new OAuth2Error("user_not_registered"),
                        "No account exists with the email: " + email
                )
        );

        var authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();

        return new DefaultOidcUser(authorities, userRequest.getIdToken(), oidcUser.getUserInfo());
    }
}
