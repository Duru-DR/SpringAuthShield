package com.duru.authentication.dto;

public record SigninRequest(
        String username,
        String password
) {}
