package com.abab.auth.config;

import com.abab.auth.model.User;
import com.abab.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;

@Configuration
@RequiredArgsConstructor
public class AdminDataLoader {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner loadAdminData() {
        return args -> {
            // 관리자 계정이 존재하는지 확인
            if (userRepository.findByEmail("admin@abab.com").isEmpty()) {
                // 비밀번호를 고정된 값으로 인코딩
                String encodedPassword = passwordEncoder.encode("admin1234");

                User adminUser = User.builder()
                        .email("admin@abab.com")
                        .password(encodedPassword)
                        .userName("adminuser")
                        .createdAt(Instant.now().getEpochSecond())
                        .passwordSetAt(Instant.now().getEpochSecond())
                        .role("ROLE_ADMIN")
                        .build();

                // 관리자 사용자 저장
                userRepository.save(adminUser);
                System.out.println("Admin user created with email: admin@abab.com");
            }
        };
    }
}
