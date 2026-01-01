package d76.app.oauth.service;

import d76.app.auth.dto.RegisterResponse;
import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.AuthProvider;
import d76.app.core.exception.BusinessException;
import d76.app.oauth.dto.SocialRegisterRequest;
import d76.app.security.jwt.JwtService;
import d76.app.security.jwt.model.JwtPurpose;
import d76.app.user.entity.Role;
import d76.app.user.entity.Users;
import d76.app.user.repo.RoleRepository;
import d76.app.user.repo.UsersRepository;
import d76.app.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class OauthService {

    private final UserService userService;
    private final JwtService jwtService;

    public RegisterResponse socialRegister(SocialRegisterRequest request) {

        //validate the token
        if(!jwtService.validateActionToken(request.actionToken(), JwtPurpose.SOCIAL_REGISTER)){
            throw new BusinessException(AuthErrorCode.INVALID_TOKEN);
        }

        //extract details
        var claims = jwtService.extractClaims(request.actionToken());
        String email = claims.getSubject();
        String providerStr = claims.get("provider", String.class).trim();

        //ensure the auth provider is valid
        AuthProvider provider;
        try{
            provider = AuthProvider.valueOf(providerStr.toUpperCase());
        }catch (IllegalArgumentException e){
            throw new BusinessException(AuthErrorCode.INVALID_AUTH_PROVIDER, "Invalid Authentication Provider: " + providerStr);
        }

        var user = userService.createOAuthUser(email, request.userName(), provider);

        return new RegisterResponse(
                user.getEmail(),
                user.getCreatedAt(),
                provider.name()
        );
    }
}
