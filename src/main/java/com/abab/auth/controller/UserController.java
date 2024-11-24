package com.abab.auth.controller;

import com.abab.auth.global.ResponseHelper;
import com.abab.auth.global.ResponseWrapper;
import com.abab.auth.model.UserWebDTO.*;
import com.abab.auth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class UserController {
    private final UserService userService;

    @PostMapping("/users/signup")
    public ResponseEntity<ResponseWrapper<GetWebResponse>> signUp(@Valid @RequestBody UserSignUpRequest request) {
        GetWebResponse response = userService.signUp(request.getEmail(), request.getPassword(), request.getUserName());
        return ResponseHelper.createResponse(response, "success", HttpStatus.CREATED);
    }

    @PostMapping("/users/login")
    public ResponseEntity<ResponseWrapper<LoginWebResponse>> login(@Valid @RequestBody UserLoginRequest request) {
        LoginWebResponse response = userService.login(request.getEmail(), request.getPassword());
        return ResponseHelper.createResponse(response, "success", HttpStatus.OK);
    }

    @PostMapping("/users/signout")
    public ResponseEntity<ResponseWrapper<Object>> signOut(@RequestHeader("Authorization") String token) {
        userService.signOut(token);
        return ResponseHelper.createResponse(null, "Logout successful", HttpStatus.OK);
    }
}
