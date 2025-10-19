package com.duru.authentication.dto;

public record RegisterResponse (
        String username,
        String email,
        String fullName
) {}
