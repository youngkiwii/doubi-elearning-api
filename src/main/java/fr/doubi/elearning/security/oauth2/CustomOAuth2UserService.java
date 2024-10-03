package fr.doubi.elearning.security.oauth2;

import fr.doubi.elearning.model.Role;
import fr.doubi.elearning.model.User;
import fr.doubi.elearning.repository.UserRepository;
import fr.doubi.elearning.security.oauth2.user.AuthProvider;
import fr.doubi.elearning.security.oauth2.user.OAuth2UserInfo;
import fr.doubi.elearning.security.oauth2.user.OAuth2UserInfoFactory;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oauth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }

    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oauth2UserRequest, OAuth2User oauth2User) {
        OAuth2UserInfo oauth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                oauth2UserRequest.getClientRegistration().getRegistrationId(),
                oauth2User.getAttributes()
        );

        if (StringUtils.isEmpty(oauth2UserInfo.getEmail())) {
            log.error("Email not found from OAuth2 provider");
            throw new RuntimeException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oauth2UserInfo.getEmail());

        User user;
        if (userOptional.isPresent()) {
            user = userOptional.get();
        } else {
            SecureRandom random = new SecureRandom();
            byte[] bytes = new byte[32];
            random.nextBytes(bytes);
            String generatedString = new String(bytes, StandardCharsets.UTF_8);

            user = User.builder().firstname(oauth2UserInfo.getName())
                    .email(oauth2UserInfo.getEmail())
                    .provider(AuthProvider.valueOf(oauth2UserRequest.getClientRegistration().getRegistrationId()))
                    .password(passwordEncoder.encode(generatedString))
                    .providerId(oauth2UserInfo.getId())
                    .role(Role.STUDENT)
                    .build();
            userRepository.save(user);
        }

        return user;
    }
}