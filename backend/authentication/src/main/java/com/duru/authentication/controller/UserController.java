package com.duru.authentication.controller;

import com.duru.authentication.dto.*;
import com.duru.authentication.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@Tag(name = "Auth", description = "API for managing user authentication")
public class UserController {
    private final UserService userService;

    @Operation(summary = "Create a new user",
            description = "Creates a new user with the provided data")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User created successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = RegisterResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation error")
    })
    @PostMapping("/auth/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest user) {
        RegisterResponse response = userService.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @Operation(summary = "User signin",
            description = "Validate user credentials and generate new access/refresh tokens")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User signed in successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = SigninResponse.class))),
            @ApiResponse(responseCode = "400", description = "Validation error")
    })
    @PostMapping("/auth/signin")
    public ResponseEntity<SigninResponse> register(@Valid @RequestBody SigninRequest request, HttpServletResponse response) {
        TokenPair tokens = userService.authenticate(request);

        String bearer = "Bearer " + tokens.accessToken();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", tokens.refreshToken())
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/api/v1/auth/refresh")
                .maxAge(Duration.between(Instant.now(), tokens.refreshExpiry()))
                .build();

        long accessTtl = Duration.between(Instant.now(), tokens.accessExpiry()).getSeconds();

        return ResponseEntity.ok()
                .header(HttpHeaders.AUTHORIZATION, bearer)
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(new SigninResponse("Signed in successfully", accessTtl));

    }
}
