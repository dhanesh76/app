package d76.app.auth.service;

import d76.app.core.exception.BusinessException;
import d76.app.auth.dto.RegisterRequest;
import d76.app.auth.dto.RegisterResponse;
import d76.app.auth.exception.AuthErrorCode;
import d76.app.auth.model.AuthProvider;
import d76.app.user.entity.Role;
import d76.app.user.entity.Users;
import d76.app.user.repo.RoleRepository;
import d76.app.user.repo.UsersRepository;
import d76.app.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    public RegisterResponse register(RegisterRequest request) {

        String encodedPassword = passwordEncoder.encode(request.password());

        var user = userService.createLocalUser(request.email(), request.userName(), encodedPassword);

        return new RegisterResponse(user.getEmail(), user.getCreatedAt(), AuthProvider.EMAIL.name());
    }
}
