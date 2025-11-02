package com.duru.authentication.unit.service;

import com.duru.authentication.dto.*;
import com.duru.authentication.exception.*;
import com.duru.authentication.model.*;
import com.duru.authentication.model.enums.Status;
import com.duru.authentication.repository.*;
import com.duru.authentication.security.jwt.JwtService;
import com.duru.authentication.service.UserService;
import com.duru.authentication.util.TokenUtil;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtService jwtService;
    @Mock private AuthenticationManager authenticationManager;
    @Mock private TokenUtil tokenUtil;

    @InjectMocks private UserService userService;

    private User user;
    private HttpServletResponse response;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .username("fatima")
                .email("fatima@mail.com")
                .fullName("Fatima Duru")
                .password("encodedPass")
                .enabled(true)
                .status(Status.ACTIVE)
                .roles(Set.of(new Role("USER")))
                .build();

        response = mock(HttpServletResponse.class);
    }

    // ---------- save() ----------
    @Test
    void shouldSaveUserSuccessfully() {
        RegisterRequest req = new RegisterRequest("fatima", "pass", "fatima@mail.com", "Fatima Duru");

        when(userRepository.existsByUsername("fatima")).thenReturn(false);
        when(userRepository.existsByEmail("fatima@mail.com")).thenReturn(false);
        when(passwordEncoder.encode("pass")).thenReturn("encodedPass");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        RegisterResponse res = userService.save(req);

        assertThat(res.username()).isEqualTo("fatima");
        assertThat(res.email()).isEqualTo("fatima@mail.com");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldThrowWhenUsernameExists() {
        RegisterRequest req = new RegisterRequest("fatima", "pass", "fatima@mail.com", "Fatima Duru");
        when(userRepository.existsByUsername("fatima")).thenReturn(true);

        assertThatThrownBy(() -> userService.save(req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("Username");
    }

    @Test
    void shouldThrowWhenEmailExists() {
        RegisterRequest req = new RegisterRequest("fatima", "pass", "fatima@mail.com", "Fatima Duru");
        when(userRepository.existsByUsername("fatima")).thenReturn(false);
        when(userRepository.existsByEmail("fatima@mail.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.save(req))
                .isInstanceOf(DuplicateResourceException.class)
                .hasMessageContaining("Email");
    }

    // ---------- login() ----------
    @Test
    void shouldLoginSuccessfully() {
        LoginRequest req = new LoginRequest("fatima", "pass");
        when(userRepository.findByUsername("fatima")).thenReturn(Optional.of(user));
        when(tokenUtil.generateAndAttachTokens(eq(user), anyCollection(), eq(response)))
                .thenReturn("accessToken");

        LoginResponse res = userService.login(req, response);

        assertThat(res.accessToken()).isEqualTo("accessToken");
        assertThat(res.message()).isEqualTo("Login successful");
    }

    @Test
    void shouldThrowWhenInvalidCredentials() {
        LoginRequest req = new LoginRequest("fatima", "wrong");
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        assertThatThrownBy(() -> userService.login(req, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Invalid username or password");
    }

    @Test
    void shouldThrowWhenUserNotFound() {
        LoginRequest req = new LoginRequest("unknown", "pass");
        when(userRepository.findByUsername("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.login(req, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("User not found");
    }

    // ---------- refresh() ----------
    @Test
    void shouldRefreshTokenSuccessfully() {
        String oldToken = "old.jwt";
        RefreshToken stored = new RefreshToken(UUID.randomUUID().toString(), user, Instant.now().plusSeconds(600));

        when(jwtService.extractUsername(oldToken)).thenReturn("fatima");
        when(jwtService.isTokenExpired(oldToken)).thenReturn(false);
        when(jwtService.extractClaim(eq(oldToken), any())).thenReturn(stored.getToken());
        when(refreshTokenRepository.findByToken(stored.getToken())).thenReturn(Optional.of(stored));
        when(tokenUtil.generateAndAttachTokens(eq(user), anyCollection(), eq(response)))
                .thenReturn("newAccessToken");

        LoginResponse res = userService.refresh(oldToken, response);

        assertThat(res.accessToken()).isEqualTo("newAccessToken");
        assertThat(res.message()).contains("refreshed");
        verify(refreshTokenRepository).delete(stored);
    }

    @Test
    void shouldThrowWhenMissingToken() {
        assertThatThrownBy(() -> userService.refresh(null, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Missing refresh token");
    }

    @Test
    void shouldThrowWhenTokenExpired() {
        String old = "expired";
        when(jwtService.extractUsername(old)).thenReturn("fatima");
        when(jwtService.isTokenExpired(old)).thenReturn(true);

        assertThatThrownBy(() -> userService.refresh(old, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Expired");
    }

    @Test
    void shouldThrowWhenInvalidStoredToken() {
        String old = "invalid";
        when(jwtService.extractUsername(old)).thenReturn("fatima");
        when(jwtService.isTokenExpired(old)).thenReturn(false);
        when(jwtService.extractClaim(eq(old), any())).thenReturn("tid");
        when(refreshTokenRepository.findByToken("tid")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.refresh(old, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    @Test
    void shouldThrowWhenStoredTokenExpired() {
        String old = "old.jwt";
        RefreshToken stored = new RefreshToken("tid", user, Instant.now().minusSeconds(60));

        when(jwtService.extractUsername(old)).thenReturn("fatima");
        when(jwtService.isTokenExpired(old)).thenReturn(false);
        when(jwtService.extractClaim(eq(old), any())).thenReturn("tid");
        when(refreshTokenRepository.findByToken("tid")).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> userService.refresh(old, response))
                .isInstanceOf(InvalidTokenException.class)
                .hasMessageContaining("expired");
    }

    // ---------- logout() ----------
    @Test
    void shouldLogoutAndDeleteToken() {
        String token = "refresh.jwt";
        when(jwtService.extractClaim(eq(token), any())).thenReturn("tid");

        userService.logout(token, response);

        verify(refreshTokenRepository).deleteByToken("tid");
        verify(tokenUtil).deleteRefreshTokenCookie(response);
    }

    @Test
    void shouldIgnoreInvalidLogoutToken() {
        String token = "bad.jwt";
        doThrow(RuntimeException.class).when(jwtService).extractClaim(eq(token), any());

        userService.logout(token, response);

        verify(tokenUtil).deleteRefreshTokenCookie(response);
    }
}
