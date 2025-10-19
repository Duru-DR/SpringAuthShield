package com.duru.authentication.dto;

import java.time.Instant;

public record TokenPair(
        String accessToken,
        String refreshToken,
        Instant accessExpiry,
        Instant refreshExpiry
) {}
