package com.duru.authentication.util;

import com.duru.authentication.model.RefreshToken;
import com.duru.authentication.model.User;
import com.duru.authentication.repository.RefreshTokenRepository;
import com.duru.authentication.security.jwt.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Collection;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenUtil {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    /**
     * Generates both access & refresh tokens, saves refresh token in DB, and adds cookie.
     */
    public String generateAndAttachTokens(User user, Collection<String> roles, HttpServletResponse response) {
        // Create refresh token record in DB
        String tokenId = UUID.randomUUID().toString();
        saveRefreshToken(user, tokenId);

        // Generate JWTs
        String accessToken = jwtService.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtService.generateRefreshToken(user.getUsername(), tokenId);

        // Set refresh token cookie
        addRefreshTokenCookie(response, refreshToken);

        // Return access token to be sent in response body
        return accessToken;
    }

    public void deleteRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = updateCookie(response, null, 0);
        response.addCookie(cookie);
    }

    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = updateCookie(response, refreshToken, 7 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    private void saveRefreshToken(User user, String tokenId) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenId)
                .user(user)
                .expiryDate(Instant.now().plusSeconds(60L * 60L * 24L * 7L)) // 7 days
                .build();
        refreshTokenRepository.save(refreshToken);
    }

    private Cookie updateCookie(HttpServletResponse response, String refreshToken, int age) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(age);

        return cookie;
    }
}
