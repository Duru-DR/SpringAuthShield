package com.duru.authentication.dto;

public record LoginResponse(
        String accessToken,
        String message
) {}
