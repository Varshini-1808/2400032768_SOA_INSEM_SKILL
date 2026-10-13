package com.example.authdemo.controller;

import com.example.authdemo.entity.User;
import com.example.authdemo.repository.UserRepository;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class UserController {

    private final UserRepository repository;
    private final BCryptPasswordEncoder encoder;

    public UserController(
            UserRepository repository,
            BCryptPasswordEncoder encoder) {
        this.repository = repository;
        this.encoder = encoder;
    }

    @PostMapping("/registerdb")
    public ResponseEntity<String> register(
            @RequestBody User input) {

        if (input.getUsername() == null
                || input.getUsername().isBlank()
                || input.getPassword() == null
                || input.getPassword().isBlank()) {

            return ResponseEntity.badRequest()
                    .body("Username and password are required");
        }

        if (repository.findByUsername(input.getUsername())
                .isPresent()) {

            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Username already exists");
        }

        User user = new User();
        user.setUsername(input.getUsername());
        user.setPassword(encoder.encode(input.getPassword()));

        repository.save(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body("User Registered Successfully");
    }

    @PostMapping("/login-db")
    public ResponseEntity<String> login(
            @RequestBody User input) {

        if (input.getUsername() == null
                || input.getPassword() == null) {

            return ResponseEntity.badRequest()
                    .body("Username and password are required");
        }

        User user = repository
                .findByUsername(input.getUsername())
                .orElse(null);

        if (user != null
                && encoder.matches(
                        input.getPassword(),
                        user.getPassword())) {

            return ResponseEntity.ok(
                    "Authentication Successful");
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Authentication Failed");
    }
}