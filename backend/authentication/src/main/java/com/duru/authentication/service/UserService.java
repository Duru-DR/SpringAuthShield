package com.duru.authentication.service;

import com.duru.authentication.dto.RegisterRequest;
import com.duru.authentication.dto.RegisterResponse;
import com.duru.authentication.dto.SigninRequest;
import com.duru.authentication.dto.TokenPair;
import com.duru.authentication.exception.DuplicateResourceException;
import com.duru.authentication.model.User;
import com.duru.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final RefreshTokenService refreshTokenService;

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
                .build();

        User saved = userRepository.save(toSave);
        return mapToResponse(saved);
    }

    public TokenPair authenticate(SigninRequest request) {
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        UserDetails principal = (UserDetails) auth.getPrincipal();

        String accessJti = UUID.randomUUID().toString();
        String refreshJti = UUID.randomUUID().toString();

        Instant now = Instant.now();
        Instant accessExp = now.plus(jwtService.getAccessTtl());
        Instant refreshExp = now.plus(jwtService.getRefreshTtl());

        String accessToken = jwtService.generateAccessToken(principal, accessJti, accessExp);
        String refreshToken = jwtService.generateRefreshToken(principal, refreshJti, refreshExp);

//        refreshTokenService.saveRefreshToken(principal.getUsername(), refreshJti, refreshExp);

        return new TokenPair(accessToken, refreshToken, accessExp, refreshExp);
    }

    private RegisterResponse mapToResponse(User user) {
        return new RegisterResponse(
                user.getUsername(),
                user.getEmail(),
                user.getFullName()
        );
    }
}
