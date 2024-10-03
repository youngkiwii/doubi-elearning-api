package fr.doubi.elearning.service;

import fr.doubi.elearning.dto.AuthenticationResponse;
import fr.doubi.elearning.dto.LoginRequest;
import fr.doubi.elearning.dto.RefreshTokenRequest;
import fr.doubi.elearning.model.RefreshToken;
import fr.doubi.elearning.model.Role;
import fr.doubi.elearning.model.User;
import fr.doubi.elearning.repository.RefreshTokenRepository;
import fr.doubi.elearning.repository.UserRepository;
import fr.doubi.elearning.security.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthenticationService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthenticationResponse register(User request) {
        User user = User.builder()
                .email(request.getEmail())
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.STUDENT)
                .build();
        userRepository.save(user);
        String accessToken = tokenService.generateToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        return AuthenticationResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    }

    public AuthenticationResponse login(LoginRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new RuntimeException("User not found"));
        String accessToken = tokenService.generateToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        return AuthenticationResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    }

    public AuthenticationResponse refreshToken(RefreshTokenRequest request) {
        RefreshToken token = refreshTokenRepository.findByToken(request.getRefreshToken()).orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        if (token.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        User user = userRepository.findByEmail(token.getUsername()).orElseThrow(() -> new RuntimeException("User not found"));
        String accessToken = tokenService.generateToken(user);
        String newRefreshToken = tokenService.generateRefreshToken(user);
        refreshTokenRepository.delete(token);
        return AuthenticationResponse.builder().accessToken(accessToken).refreshToken(newRefreshToken).build();
    }
}
