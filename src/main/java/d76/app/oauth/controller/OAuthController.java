package d76.app.oauth.controller;

import d76.app.oauth.dto.SocialRegisterRequest;
import d76.app.oauth.service.OauthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/oauth")
@RequiredArgsConstructor
@NullMarked
public class OAuthController {

    private final OauthService oauthService;

    @PostMapping("/register")
    ResponseEntity<?> socialRegister(@RequestBody @Valid SocialRegisterRequest request) {
        var response = oauthService.socialRegister(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
