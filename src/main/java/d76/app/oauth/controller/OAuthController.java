package d76.app.oauth.controller;

import d76.app.oauth.dto.SocialRegisterRequest;
import d76.app.oauth.service.OauthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/oauth/")
@RequiredArgsConstructor
public class OAuthController {

    private final OauthService oauthService;

    @PostMapping("/register")
    ResponseEntity<?> socialRegister(SocialRegisterRequest request){
        var response = oauthService.socialRegister(request);
        return null;
    }
}
