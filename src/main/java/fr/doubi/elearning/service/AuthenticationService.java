package fr.doubi.elearning.service;

import fr.doubi.elearning.dto.auth.AuthenticationResponse;
import fr.doubi.elearning.dto.auth.LoginRequest;
import fr.doubi.elearning.dto.auth.RefreshTokenRequest;
import fr.doubi.elearning.model.ResetPasswordToken;
import fr.doubi.elearning.model.RefreshToken;
import fr.doubi.elearning.model.Role;
import fr.doubi.elearning.model.User;
import fr.doubi.elearning.repository.RefreshTokenRepository;
import fr.doubi.elearning.repository.ResetPasswordTokenRepository;
import fr.doubi.elearning.repository.UserRepository;
import fr.doubi.elearning.security.TokenService;
import fr.doubi.elearning.util.RandomUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JavaMailSender mailSender;
    private final ResetPasswordTokenRepository resetPasswordTokenRepository;

    public void register(User request) {
        String emailVerificationToken = RandomUtils.generateRandomString(32);

        User user = User.builder()
                .email(request.getEmail())
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .password(passwordEncoder.encode(request.getPassword()))
                .emailVerificationToken(emailVerificationToken)
                .role(Role.STUDENT)
                .build();
        userRepository.save(user);
        sendVerificationEmail(user);
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

    public String verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token).orElseThrow(() -> new RuntimeException("Invalid token"));
        user.setEmailVerificationToken(null);
        userRepository.save(user);
        String accessToken = tokenService.generateToken(user);
        String newRefreshToken = tokenService.generateRefreshToken(user);

        return "http://localhost:4200/login?access_token=" + accessToken + "&refresh_token=" + newRefreshToken;
    }

    public void sendVerificationEmail(User user) {
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        log.info("Sending email verification to {}", user.getEmail());
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Complete Registration!");
        mailMessage.setFrom("Alex le gentil <noreply@doubi.fr>");
        mailMessage.setText("To confirm your account, please click here : "
                + "http://localhost:8080/api/auth/verify?token=" + user.getEmailVerificationToken());
        mailSender.send(mailMessage);
    }

    public void forgotPassword(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        if (user.isEmpty()) return;

        String token = RandomUtils.generateRandomString(32);
        ResetPasswordToken resetPasswordToken = ResetPasswordToken.builder()
                .token(token)
                .expiryDate(Instant.now().plusMillis(15 * 60 * 1000))
                .user(user.get())
                .build();
        resetPasswordTokenRepository.save(resetPasswordToken);
        sendResetPasswordEmail(user.get(), token);
    }

    public void sendResetPasswordEmail(User user, String token) {
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        log.info("Sending email reset password to {}", user.getEmail());
        mailMessage.setTo(user.getEmail());
        mailMessage.setSubject("Reset your password!");
        mailMessage.setFrom("Alex le gentil <noreply@doubi.fr>");
        mailMessage.setText("To reset your password, please click here : "
                + "http://localhost:4200/reset-password?token=" + token);
        mailSender.send(mailMessage);
    }

    public void verifyResetPasswordToken(String token) {
        ResetPasswordToken resetPasswordToken = resetPasswordTokenRepository.findByToken(token).orElseThrow(() -> new RuntimeException("Invalid token"));
        if (resetPasswordToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired");
        }
    }

    public void resetPassword(String token, String password) {
        ResetPasswordToken resetPasswordToken = resetPasswordTokenRepository.findByToken(token).orElseThrow(() -> new RuntimeException("Invalid token"));
        if (resetPasswordToken.getExpiryDate().isBefore(Instant.now())) {
            throw new RuntimeException("Token expired");
        }
        User user = resetPasswordToken.getUser();
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
        resetPasswordTokenRepository.delete(resetPasswordToken);
    }
}
