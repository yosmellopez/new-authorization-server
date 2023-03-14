package com.pichincha.usersservice.web.rest;

import com.pichincha.usersservice.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api")
public class UserResource {
    private final UserService userService;

    public UserResource(UserService userService) {
        this.userService = userService;
    }

    @GetMapping(value = "/account")
    public ResponseEntity<Object> getPrincipal() {
        Optional<User> optionalUser = userService.getCurrenUser();
        return ResponseEntity.ok(optionalUser.orElseThrow());
    }
}
