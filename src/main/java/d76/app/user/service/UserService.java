package d76.app.user.service;

import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.AuthProvider;
import d76.app.core.exception.BusinessException;
import d76.app.user.entity.Role;
import d76.app.user.entity.Users;
import d76.app.user.repo.RoleRepository;
import d76.app.user.repo.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UsersRepository usersRepository;
    private final RoleRepository roleRepository;

    private final String DEFAULT_ROLE = "USER";

    @Transactional
    public Users createLocalUser(String email, String username, String encodedPassword){

        //ensure the availability
        assertEmailAvailable(email);
        assertUsernameAvailable(username);

        Role role = loadDefaultRole();
        Set<Role> roles = new HashSet<>(Set.of(role));

        Set<AuthProvider> authProviders = new HashSet<>(Set.of(AuthProvider.EMAIL));

        Users user = Users.builder()
                .username(username)
                .email(email)
                .password(encodedPassword)
                .authProviders(authProviders)
                .roles(roles)
                .build();

        return usersRepository.save(user);
    }

    @Transactional
    public Users createOAuthUser(String email, String username, AuthProvider authProvider){

        assertUsernameAvailable(username);
        assertEmailAvailable(email);

        Role role = loadDefaultRole();
        Set<Role> roles = new HashSet<>(Set.of(role));

        Set<AuthProvider> authProviders = new HashSet<>(Set.of(authProvider));

        Users user = Users
                .builder()
                .username(username)
                .email(email)
                .authProviders(authProviders)
                .roles(roles)
                .build();

        return usersRepository.save(user);
    }

    //helper
    public void assertEmailAvailable(String email) {
        if (usersRepository.existsByEmail(email)) {
            throw new BusinessException(AuthErrorCode.EMAIL_ALREADY_REGISTERED);
        }
    }

    public void assertUsernameAvailable(String username) {
        if (usersRepository.existsByUsername(username)) {
            throw new BusinessException(AuthErrorCode.USERNAME_TAKEN);
        }
    }

    private Role loadDefaultRole(){
        return roleRepository.findByName(DEFAULT_ROLE).orElseThrow(
                () -> new BusinessException(AuthErrorCode.ROLE_NOT_FOUND, "No role exists with name: " + DEFAULT_ROLE)
        );
    }
}
