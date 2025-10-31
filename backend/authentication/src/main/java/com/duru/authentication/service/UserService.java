package com.duru.authentication.service;

import com.duru.authentication.dto.LoginRequest;
import com.duru.authentication.dto.LoginResponse;
import com.duru.authentication.dto.RegisterRequest;
import com.duru.authentication.dto.RegisterResponse;
import com.duru.authentication.exception.DuplicateResourceException;
import com.duru.authentication.exception.InvalidTokenException;
import com.duru.authentication.model.AuditInfo;
import com.duru.authentication.model.RefreshToken;
import com.duru.authentication.model.Role;
import com.duru.authentication.model.User;
import com.duru.authentication.model.enums.Status;
import com.duru.authentication.repository.RefreshTokenRepository;
import com.duru.authentication.repository.UserRepository;
import com.duru.authentication.security.jwt.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collection;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public RegisterResponse save(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new DuplicateResourceException("Username already exists");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new DuplicateResourceException("Email already exists");
        }

        User toSave = User.builder()
                .username(request.username())
                .email(request.email())
                .fullName(request.fullName())
                .password(passwordEncoder.encode(request.password()))
                .enabled(true)
                .status(Status.ACTIVE)
                .auditInfo(new AuditInfo())
                .build();

        User saved = userRepository.save(toSave);
        return mapToResponse(saved);
    }

    public LoginResponse login(LoginRequest request, HttpServletResponse response) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );
        } catch (AuthenticationException e) {
            throw new InvalidTokenException("Invalid username or password");
        }

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        Collection<String> roles = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        String tokenId = UUID.randomUUID().toString();
        saveRefreshToken(user, tokenId);

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(user.getUsername(), roles);
        String refreshToken = jwtService.generateRefreshToken(user.getUsername(), tokenId);

        addRefreshTokenCookie(response, refreshToken);

        return new LoginResponse(accessToken, "Login successful");
    }

    @Transactional
    public LoginResponse refresh(String oldRefreshToken, HttpServletResponse response) {
        if (oldRefreshToken == null)
            throw new InvalidTokenException("Missing refresh token");

        String username = jwtService.extractUsername(oldRefreshToken);
        if (jwtService.isTokenExpired(oldRefreshToken))
            throw new InvalidTokenException("Expired refresh token");

        String tokenId = jwtService.extractClaim(oldRefreshToken, claims -> claims.get("tid", String.class));

        RefreshToken storedToken = refreshTokenRepository.findByToken(tokenId)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (storedToken.getExpiryDate().isBefore(Instant.now()))
            throw new InvalidTokenException("Refresh token expired");

        User user = storedToken.getUser();

        // Remove old token record
        refreshTokenRepository.delete(storedToken);

        // Create new one
        String newTokenId = UUID.randomUUID().toString();
        saveRefreshToken(user, newTokenId);

        Collection<String> roles = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        String newAccessToken = jwtService.generateAccessToken(user.getUsername(), roles);
        String newRefreshToken = jwtService.generateRefreshToken(user.getUsername(), newTokenId);

        addRefreshTokenCookie(response, newRefreshToken);

        return new LoginResponse(newAccessToken, "Tokens refreshed");
    }

    @Transactional
    public void logout(String refreshToken, HttpServletResponse response) {
        if (refreshToken != null) {
            try {
                String tokenId = jwtService.extractClaim(refreshToken, claims -> claims.get("tid", String.class));
                refreshTokenRepository.deleteByToken(tokenId);
            } catch (Exception ignored) {
                // ignore invalid token during logout
            }
        }
        deleteRefreshTokenCookie(response);
    }

    private void saveRefreshToken(User user, String token) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiryDate(Instant.now().plusSeconds(60L * 60L * 24L * 7L)) // 7 days
                .build();
        refreshTokenRepository.save(refreshToken);
    }

    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60);
        response.addCookie(cookie);
    }

    private void deleteRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refresh_token", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private RegisterResponse mapToResponse(User user) {
        return new RegisterResponse(
                user.getUsername(),
                user.getEmail(),
                user.getFullName()
        );
    }
}
