package com.duru.authentication.dto;

public record LoginRequest(
        String username,
        String password
) {}
