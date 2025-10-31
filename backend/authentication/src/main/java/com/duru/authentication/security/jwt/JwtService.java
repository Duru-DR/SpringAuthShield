package com.duru.authentication.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    private final Key key;
    private final long accessTokenMillis;
    private final long refreshTokenMillis;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.access-token-exp-ms:900000}") long accessTokenMillis,
            @Value("${app.jwt.refresh-token-exp-ms:2592000000}") long refreshTokenMillis // 30 days
    ) {
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        this.accessTokenMillis = accessTokenMillis;
        this.refreshTokenMillis = refreshTokenMillis;
    }

    public String generateAccessToken(String username, Collection<String> authorities) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authorities);
        return buildToken(claims, username, accessTokenMillis);
    }

    public String generateRefreshToken(String username, String tokenId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("tid", tokenId);
        return buildToken(claims, username, refreshTokenMillis);
    }

    private String buildToken(Map<String,Object> claims, String subject, long ttlMillis) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(ttlMillis);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .signWith(key)
                .compact();
    }

    public boolean isTokenValid(String token, String username) {
        final String sub = extractUsername(token);
        return (sub.equals(username) && !isTokenExpired(token));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, @org.jetbrains.annotations.NotNull Function<Claims,T> resolver) {
        Claims claims = Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return resolver.apply(claims);
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }
}
