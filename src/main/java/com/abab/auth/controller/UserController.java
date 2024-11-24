package com.abab.auth.controller;

import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class UserController {
    private final UserService userService;

    @PostMapping("/users/signup")
    public ResponseEntity<GetWebResponse> signUp(@Valid @RequestBody UserSignUpRequest request) {
        GetWebResponse response = userService.signUp(request.getEmail(), request.getPassword(), request.getUserName());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/signin")
    public ResponseEntity<LoginWebResponse> signIn(@Valid @RequestBody UserLoginRequest request) {
        LoginWebResponse response = userService.signIn(request.getEmail(), request.getPassword());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/users/signout")
    public ResponseEntity<String> signOut(@RequestHeader("Authorization") String token) {
        userService.signOut(token);
        return ResponseEntity.ok("Logout successful");
    }
}
