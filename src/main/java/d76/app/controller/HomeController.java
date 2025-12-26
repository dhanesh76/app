package d76.app.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Properties;

@RestController
@EnableMethodSecurity
public class HomeController {

    @GetMapping("/")
    Properties home(){
        return  System.getProperties();
    }

    @GetMapping("/user/secured")
    @PreAuthorize("hasRole('USER')")
    String secured(){
        return "You are seeing this because you are authenticated";
    }


    @GetMapping("/admin/secured")
    @PreAuthorize("hasRole('ADMIN')")
    String adminSecured(){
        return "You are seeing this because you are admin";
    }
}
