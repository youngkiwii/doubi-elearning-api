package fr.doubi.elearning.controller;

import fr.doubi.elearning.dto.auth.AuthenticationResponse;
import fr.doubi.elearning.dto.auth.LoginRequest;
import fr.doubi.elearning.dto.auth.RefreshTokenRequest;
import fr.doubi.elearning.dto.auth.ResetPasswordRequest;
import fr.doubi.elearning.model.User;
import fr.doubi.elearning.repository.UserRepository;
import fr.doubi.elearning.security.CurrentUser;
import fr.doubi.elearning.service.AuthenticationService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody User request) {
        authenticationService.register(request);
        Map<String, Object> response = new HashMap<>();
        response.put("message", "An email has been sent to " + request.getEmail() + " for verification");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
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

    @GetMapping("/verify")
    public ResponseEntity<String> verifyEmail(@RequestParam String token) {
        String url = authenticationService.verifyEmail(token);
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<Object> forgotPassword(@RequestBody Map<String, String> request) {
        log.info("Forgot password request received for email: {}", request.get("email"));
        authenticationService.forgotPassword(request.get("email"));
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Password reset email sent successfully");
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/reset-password/verify")
    public ResponseEntity<Object> verifyResetPasswordToken(@RequestBody Map<String, String> request) {
        authenticationService.verifyResetPasswordToken(request.get("token"));
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Token verified successfully");
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Object> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authenticationService.resetPassword(request.getToken(), request.getPassword());
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Password updated successfully");
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
