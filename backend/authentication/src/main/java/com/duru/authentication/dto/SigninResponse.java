package com.duru.authentication.dto;

public record SigninResponse(
        String message,
        long accessTokenExpiresInSeconds
) {}
