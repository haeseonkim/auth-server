package com.abab.auth.service;

import com.abab.auth.model.User;
import com.abab.auth.model.UserMapper;
import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder;

    public GetWebResponse signUp(String email, String password, String username) {
        if (isEmailAlreadyInUse(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email is already in use");
        }

        User user = createUser(email, password, username);
        User savedUser = saveUser(user);
        return UserMapper.INSTANCE.toWebDto(savedUser);
    }

    private boolean isEmailAlreadyInUse(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    private User createUser(String email, String password, String username) {
        return User.builder()
                .email(email)
                .password(passwordEncoder.encode(password))
                .userName(username)
                .createdAt(Instant.now().getEpochSecond())
                .build();
    }

    private User saveUser(User user) {
        return userRepository.save(user);
    }
}
