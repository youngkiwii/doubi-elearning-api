package fr.doubi.elearning.controller;

import fr.doubi.elearning.dto.AuthenticationResponse;
import fr.doubi.elearning.dto.LoginRequest;
import fr.doubi.elearning.dto.RefreshTokenRequest;
import fr.doubi.elearning.model.User;
import fr.doubi.elearning.repository.UserRepository;
import fr.doubi.elearning.security.CurrentUser;
import fr.doubi.elearning.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody User request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authenticationService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authenticationService.refreshToken(request));
    }

    @GetMapping("/me")
    public ResponseEntity<UserDetails> getCurrentUser(@CurrentUser UserDetails userDetails) {
        return ResponseEntity.ok(userDetails);
    }
}
