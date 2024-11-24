package com.abab.auth.controller;

import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class UserController {
    private final UserService userService;

    @PostMapping("/users/signup")
    public ResponseEntity<GetWebResponse> signUp(@Valid @RequestBody UserSignUpRequest request) {
        GetWebResponse response = userService.signUp(request.getEmail(), request.getPassword(), request.getUserName());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
