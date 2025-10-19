package com.duru.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "username is required")
        @Size(min = 3, max = 30, message = "username must be between 3 and 30 characters")
        @Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "username can only contain letters, numbers, ., -, _")
        String username,

        @NotBlank(message = "password is required")
        @Size(min = 8, max = 72, message = "password must be at least 8 characters and at most 72")
        @Pattern(regexp = "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$", message = "Password must be at least 8 characters and include upper, lower, number, and symbol with no spaces.")
        String password,

        @NotBlank(message = "email is required")
        @Email(message = "email must be valid")
        String email,

        @Size(min = 2, max = 100, message = "fullName must be between 2 and 100 characters")
        String fullName
) {
    public RegisterRequest {
        if (username != null) username = username.trim();
        if (email != null) email = email.trim().toLowerCase();
        if (fullName != null) fullName = fullName.trim();
    }
}
