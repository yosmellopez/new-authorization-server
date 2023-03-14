package com.pichincha.usersservice.service;

import com.pichincha.usersservice.security.SecurityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Service class for managing users.
 */
@Service
@Transactional
public class UserService {

    public Optional<User> getCurrenUser() {
        return SecurityUtils.getCurrentUserLogin()
                .map(s -> new User(s, s, null));
    }
}
