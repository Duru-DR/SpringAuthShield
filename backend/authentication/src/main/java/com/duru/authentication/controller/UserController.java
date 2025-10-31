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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/*
fix the access token return
fix the auditing not working problem
* */

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

    @Operation(summary = "Login user",
            description = "Authenticates a user using username and password, returns access and refresh tokens")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {
        return ResponseEntity.ok(userService.login(request, response));
    }

    @Operation(summary = "Refresh access token",
            description = "Uses refresh token (from cookie) to issue new access and refresh tokens")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Tokens refreshed successfully",
                    content = @Content(mediaType = "application/json",
                            schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "403", description = "Invalid or expired refresh token")
    })
    @PostMapping("/auth/refresh")
    public ResponseEntity<LoginResponse> refresh(HttpServletResponse response,
                                                @CookieValue(name = "refresh_token", required = false) String refreshToken) {
        return ResponseEntity.ok(userService.refresh(refreshToken, response));
    }

    @Operation(summary = "Logout user",
            description = "Logs out user by deleting the refresh token from database and cookie")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Logout successful"),
            @ApiResponse(responseCode = "400", description = "No refresh token found")
    })
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refresh_token", required = false) String refreshToken,
                                       HttpServletResponse response) {
        userService.logout(refreshToken, response);
        return ResponseEntity.ok().build();
    }
}
