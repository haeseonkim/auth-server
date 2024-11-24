package com.abab.auth.service;

import com.abab.auth.model.User;
import com.abab.auth.model.UserMapper;
import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.repository.UserRepository;
import com.abab.auth.util.JwtTokenUtil;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;

    @Getter
    private final Set<String> validTokens = ConcurrentHashMap.newKeySet();  // Thread-safe한 유효 토큰 관리

    private static final long PASSWORD_EXPIRATION_DAYS = 90;


    public GetWebResponse signUp(String email, String password, String username) {
        if (isEmailAlreadyInUse(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already in use");
        }

        User user = createUser(email, password, username);
        User savedUser = saveUser(user);
        return UserMapper.INSTANCE.toWebDto(savedUser);
    }

    public LoginWebResponse login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("로그인 실패 - 이메일 존재하지 않음: {}", email);
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "email or password incorrect");
                });

        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("로그인 실패 - 비밀번호 불일치: {}", email);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "email or password incorrect");
        }

        if (isPasswordExpired(user)) {
            log.warn("로그인 실패 - 비밀번호 기간 만료: {}", email);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "password expired"); // 비번 설정 90일 지남
        }

        String token = jwtTokenUtil.generateToken(user.getEmail());
        validTokens.add(token);
        Date issuedAt = jwtTokenUtil.getIssuedAtDateFromToken(token);
        Date expiration = jwtTokenUtil.getExpirationDateFromToken(token);

        log.info("로그인 성공: {}", email);

        return UserMapper.INSTANCE.toLoginWebResponse(user, token, issuedAt.getTime() / 1000, expiration.getTime() / 1000);
    }

    // 로그아웃 메서드 구현
    public void signOut(String token) {
        if (token.startsWith("Bearer ")) {
            token = token.substring(7); // "Bearer " 부분 제거
        }

        if (!validTokens.contains(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "invalid token");
        }

        validTokens.remove(token);  // 로그아웃 시 유효한 토큰에서 제거
        log.info("로그아웃 성공: {}", token);
    }

    private boolean isEmailAlreadyInUse(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    private User createUser(String email, String password, String username) {
        long currentTime = Instant.now().getEpochSecond();
        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .userName(username)
                .createdAt(currentTime)
                .passwordSetAt(currentTime)
                .build();
    }

    private User saveUser(User user) {
        return userRepository.save(user);
    }

    private boolean isPasswordExpired(User user) {
        long currentTime = Instant.now().getEpochSecond();
        long ninetyDaysInSeconds = PASSWORD_EXPIRATION_DAYS * 24 * 60 * 60;
        return (currentTime - user.getPasswordSetAt()) > ninetyDaysInSeconds;
    }
}
