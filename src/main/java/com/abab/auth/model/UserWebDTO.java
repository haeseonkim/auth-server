package com.abab.auth.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;

public class UserWebDTO {

    private UserWebDTO() {
        throw new IllegalStateException("Dto group class");
    }

    @Getter
    @Builder
    public static class GetWebResponse {
        private String userName;
        private String email;
        private long createdAt;
    }

    @Getter
    public static class UserSignUpRequest {
        @NotBlank(message = "Email is mandatory")
        @Email(message = "Email should be valid")
        private String email;

        @NotBlank(message = "Password is mandatory")
        @Size(min = 6, max = 20, message = "Password must be between 6 and 20 characters")
        private String password;

        @NotBlank(message = "Username is mandatory")
        private String userName;
    }
}
