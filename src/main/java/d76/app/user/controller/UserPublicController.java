package d76.app.user.controller;

import d76.app.user.dto.LinkProviderRequest;
import d76.app.user.dto.UserNameAvailabilityCheckResponse;
import d76.app.user.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@NullMarked
public class UserPublicController {

    private final UserService userService;

    @PostMapping("/auth-providers")
    @ResponseStatus(code = HttpStatus.NO_CONTENT)
    void linkAuthProvider(@RequestBody @Valid LinkProviderRequest request) {
        userService.linkAuthProvider(request.actionToken());
    }

    @GetMapping("/availability/username")
    @ResponseStatus(code = HttpStatus.OK)
    UserNameAvailabilityCheckResponse isUserNameAvailable(@RequestParam("username") String username) {
        boolean isAvailable = userService.isUserNameAvailable(username);
        return new UserNameAvailabilityCheckResponse(isAvailable);
    }
}
