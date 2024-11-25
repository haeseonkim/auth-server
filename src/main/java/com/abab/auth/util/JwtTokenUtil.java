package com.abab.auth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtTokenUtil {
    private final SecretKey secretKey;
    private static final long EXPIRATION_TIME = 3600L * 1000L; // 1시간

    public JwtTokenUtil(@Value("${jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateToken(Long userId, String role) {
        // 주제(subject)를 User ID로 설정하여 JWT 토큰 생성
        return Jwts.builder()
                .setSubject(String.valueOf(userId))  // User ID를 주제로 설정
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .compact();
    }

    public String getRoleFromToken(String token) {
        // 토큰에서 역할 정보 추출
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("role", String.class);
    }

    public String getUsernameFromToken(String token) {
        // 토큰에서 사용자 이름(주제) 추출
        Claims claims = getAllClaimsFromToken(token);
        return claims.getSubject();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return Long.parseLong(claims.getSubject()); // subject를 userId로 사용
    }

    public Date getIssuedAtDateFromToken(String token) {
        // 토큰에서 발급일 추출
        Claims claims = getAllClaimsFromToken(token);
        return claims.getIssuedAt();
    }

    public Date getExpirationDateFromToken(String token) {
        // 토큰에서 만료일 추출
        Claims claims = getAllClaimsFromToken(token);
        return claims.getExpiration();
    }

    private Claims getAllClaimsFromToken(String token) {
        // 토큰을 파싱하여 모든 클레임(claims) 추출
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
