package com.abab.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)  // CSRF 보호 비활성화
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/v1/auth/users/signup").permitAll()  // 회원가입은 인증 없이 접근 가능
                        .requestMatchers("/h2-console/**").permitAll()  // H2 콘솔 접근 허용
                        .anyRequest().authenticated()  // 그 외 모든 요청은 인증 필요
                )
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin) // H2 콘솔의 iframe 사용을 허용
                )
                .httpBasic(AbstractHttpConfigurer::disable)  // httpBasic 인증 비활성화
                .formLogin(AbstractHttpConfigurer::disable);  // 폼 로그인 비활성화

        return http.build();
    }
}
