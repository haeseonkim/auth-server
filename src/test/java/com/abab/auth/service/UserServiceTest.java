package com.abab.auth.service;

import com.abab.auth.model.User;
import com.abab.auth.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private BCryptPasswordEncoder passwordEncoder;

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
}
