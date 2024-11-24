package com.abab.auth.service;

import com.abab.auth.model.User;
import com.abab.auth.model.UserWebDTO;
import com.abab.auth.repository.UserRepository;
import com.abab.auth.util.JwtTokenUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenUtil jwtTokenUtil;

    @InjectMocks
    private UserService userService;

    private final String email = "test@ab180.co";
    private final String password = "abcd1234";
    private final String userName = "testuser";

    @Nested
    @DisplayName("SignUpTests")
    class SignUpTests {

        @Test
        @DisplayName("사용 중인 이메일이 아닐때 => 회원 가입 성공 응답 반환")
        void testSignUpSuccess() {
            // Given
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());
            when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");

            User userToSave = User.builder()
                    .email(email)
                    .password("encodedPassword")
                    .userName(userName)
                    .createdAt(Instant.now().getEpochSecond())
                    .build();

            when(userRepository.save(any(User.class))).thenReturn(userToSave);
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);

            // When
            userService.signUp(email, password, userName);

            // Then
            verify(userRepository, times(1)).findByEmail(email);
            verify(userRepository, times(1)).save(userCaptor.capture());

            User capturedUser = userCaptor.getValue();

            assertEquals(email, capturedUser.getEmail(), "Captured user's email should match");
            assertEquals("encodedPassword", capturedUser.getPassword(), "Captured user's password should be encoded");
            assertEquals(userName, capturedUser.getUserName(), "Captured user's username should match");

        }

        @Test
        @DisplayName("이미 사용 중인 이메일 => throw ResponseStatusException")
        void testSignUpEmailAlreadyInUse() {
            // Given
            when(userRepository.findByEmail(email)).thenReturn(Optional.of(User.builder()
                    .email(email)
                    .password(password)
                    .userName(userName)
                    .createdAt(Instant.now().getEpochSecond())
                    .build()));

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
                userService.signUp(email, password, userName);
            });

            assertEquals(HttpStatus.BAD_REQUEST, exception.getStatusCode(), "Should return BAD_REQUEST status");
            verify(userRepository, times(1)).findByEmail(email);
            verify(userRepository, never()).save(any(User.class));
        }
    }

    @Nested
    @DisplayName("LoginTests")
    class LoginTests {

        @Test
        @DisplayName("올바른 이메일과 비밀번호 => 로그인 성공")
        void testLoginSuccess() {
            // Given
            User user = User.builder()
                    .email(email)
                    .password("encodedPassword")
                    .userName(userName)
                    .passwordSetAt(Instant.now().getEpochSecond())
                    .build();

            Date issuedAt = new Date();
            Date expiration = new Date(issuedAt.getTime() + 3600 * 1000);

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(password, user.getPassword())).thenReturn(true);
            when(jwtTokenUtil.generateToken(email)).thenReturn("testToken");
            when(jwtTokenUtil.getIssuedAtDateFromToken("testToken")).thenReturn(issuedAt);
            when(jwtTokenUtil.getExpirationDateFromToken("testToken")).thenReturn(expiration);

            // When
            UserWebDTO.LoginWebResponse response = userService.login(email, password);

            // Then
            assertNotNull(response);
            assertEquals("testToken", response.getToken(), "The token should match the generated token");
            verify(userRepository, times(1)).findByEmail(email);
        }

        @Test
        @DisplayName("이메일이 존재하지 않을 때 => throw ResponseStatusException")
        void testLoginEmailNotFound() {
            // Given
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
                userService.login(email, password);
            });

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode(), "Should return UNAUTHORIZED status");
            assertEquals("이메일 또는 비밀번호가 잘못되었습니다.", exception.getReason());
        }

        @Test
        @DisplayName("비밀번호 불일치 => throw ResponseStatusException")
        void testLoginPasswordMismatch() {
            // Given
            User user = User.builder()
                    .email(email)
                    .password("encodedPassword")
                    .userName(userName)
                    .build();

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(password, user.getPassword())).thenReturn(false);

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
                userService.login(email, password);
            });

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode(), "Should return UNAUTHORIZED status");
            assertEquals("이메일 또는 비밀번호가 잘못되었습니다.", exception.getReason());
        }

        @Test
        @DisplayName("비밀번호가 만료되었을 때 => throw ResponseStatusException")
        void testLoginPasswordExpired() {
            // Given
            User user = User.builder()
                    .email(email)
                    .password("encodedPassword")
                    .userName(userName)
                    .passwordSetAt(Instant.now().minusSeconds(90 * 24 * 60 * 60 + 1).getEpochSecond())
                    .build();

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(password, user.getPassword())).thenReturn(true);

            // When & Then
            ResponseStatusException exception = assertThrows(ResponseStatusException.class, () -> {
                userService.login(email, password);
            });

            assertEquals(HttpStatus.UNAUTHORIZED, exception.getStatusCode(), "Should return UNAUTHORIZED status");
            assertEquals("비밀번호 설정 후 90일이 지나 로그인이 불가능합니다.", exception.getReason());
        }
    }
}