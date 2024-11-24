package com.abab.auth.service;

import com.abab.auth.model.User;
import com.abab.auth.model.UserMapper;
import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.repository.UserRepository;
import com.abab.auth.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Date;
import java.util.logging.Logger;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
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
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 잘못되었습니다.");
                });

        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("로그인 실패 - 비밀번호 불일치: {}", email);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 잘못되었습니다.");
        }

        if (isPasswordExpired(user)) {
            log.warn("로그인 실패 - 비밀번호 기간 만료: {}", email);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "비밀번호 설정 후 90일이 지나 로그인이 불가능합니다.");
        }

        String token = jwtTokenUtil.generateToken(user.getEmail());
        Date issuedAt = jwtTokenUtil.getIssuedAtDateFromToken(token);
        Date expiration = jwtTokenUtil.getExpirationDateFromToken(token);

        log.info("로그인 성공: {}", email);

        return UserMapper.INSTANCE.toLoginWebResponse(user, token, issuedAt.getTime() / 1000, expiration.getTime() / 1000);
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
