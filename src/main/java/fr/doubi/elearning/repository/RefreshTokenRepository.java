package fr.doubi.elearning.repository;

import fr.doubi.elearning.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer> {
    public Optional<RefreshToken> findByToken(String token);
}
