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
import com.duru.authentication.util.TokenUtil;
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
    private final TokenUtil tokenUtil;

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

        String accessToken = tokenUtil.generateAndAttachTokens(user, roles, response);
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

        Collection<String> roles = user.getRoles()
                .stream()
                .map(Role::getName)
                .collect(Collectors.toList());

        String accessToken = tokenUtil.generateAndAttachTokens(user, roles, response);
        return new LoginResponse(accessToken, "Tokens refreshed");
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
        tokenUtil.deleteRefreshTokenCookie(response);
    }

    private RegisterResponse mapToResponse(User user) {
        return new RegisterResponse(
                user.getUsername(),
                user.getEmail(),
                user.getFullName()
        );
    }
}
