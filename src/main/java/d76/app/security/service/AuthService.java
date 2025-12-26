package d76.app.security.service;

import d76.app.exception.BusinessException;
import d76.app.security.dto.RegisterRequest;
import d76.app.security.dto.RegisterResponse;
import d76.app.security.exception.AuthErrorCode;
import d76.app.security.model.AuthProviders;
import d76.app.user.entity.Role;
import d76.app.user.entity.Users;
import d76.app.user.repo.RoleRepository;
import d76.app.user.repo.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private  final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    private static final String DEFAULT_ROLE = "USER";

    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        if(usersRepository.existsByEmail(request.email())){
            throw new BusinessException(AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        }

        if(usersRepository.existsByUsername(request.userName())){
            throw new BusinessException(AuthErrorCode.USERNAME_TAKEN);
        }


        Role role = roleRepository.findByName(DEFAULT_ROLE).orElseThrow(
                () -> new BusinessException(AuthErrorCode.ROLE_NOT_FOUND, "No role exists with name: " + DEFAULT_ROLE)
        );

        Set<Role> roles = new HashSet<>();
        roles.add(role);

        Set<AuthProviders> authProviders = new HashSet<>();
        authProviders.add(AuthProviders.EMAIL);

        Users user = Users.builder()
                .username(request.userName())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .authProviders(authProviders)
                .roles(roles)
                .build();

        usersRepository.save(user);
        return new RegisterResponse(user.getEmail(), user.getCreatedAt());
    }
}
