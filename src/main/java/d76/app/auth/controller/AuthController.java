package d76.app.auth.controller;

import d76.app.auth.dto.ForgotPasswordRequest;
import d76.app.auth.dto.RegisterRequest;
import d76.app.auth.dto.RegisterResponse;
import d76.app.auth.dto.ResetPasswordRequest;
import d76.app.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@NullMarked
@RestController
@RequiredArgsConstructor
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    ResponseEntity<RegisterResponse> register(@RequestBody @Valid RegisterRequest request) {

        RegisterResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/password/forgot")
    @ResponseStatus(HttpStatus.OK)
    void forgotPassword(@RequestBody @Valid ForgotPasswordRequest request) {
        authService.forgotPassword(request.email());
    }

    @PostMapping("/password/reset")
    @ResponseStatus(code = HttpStatus.OK)
    void resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authService.resetPassword(request);
    }
}
