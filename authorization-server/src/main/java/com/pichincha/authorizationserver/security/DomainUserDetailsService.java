package com.pichincha.authorizationserver.security;

import com.pichincha.authorizationserver.domain.AppUser;
import com.pichincha.authorizationserver.domain.Authority;
import com.pichincha.authorizationserver.repository.UserRepository;
import org.hibernate.validator.internal.constraintvalidators.hv.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Authenticate a user from the database.
 */
@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {
    private final Logger log = LoggerFactory.getLogger(DomainUserDetailsService.class);
    private final UserRepository userRepository;

    public DomainUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        log.debug("Authenticating {}", username);
        if (new EmailValidator().isValid(username, null)) {
            return userRepository.findOneWithAuthoritiesByEmail(username)
                    .map(appUser -> this.createSpringSecurityUser(appUser, new ArrayList<>(appUser.getAuthorities())))
                    .orElseThrow(() -> new UsernameNotFoundException("AppUser with email " + username + " was not found in the database"));
        }

        String lowercaseUsername = username.toLowerCase(Locale.ENGLISH);
        return userRepository.findOneWithAuthoritiesByUsername(lowercaseUsername)
                .map(user -> createSpringSecurityUser(user, new ArrayList<>(user.getAuthorities())))
                .orElseThrow(() -> new UsernameNotFoundException("AppUser " + lowercaseUsername + " was not found in the database"));
    }

    private User createSpringSecurityUser(AppUser user, List<Authority> authorities) {
        if (!user.isActivated()) {
            String lowercaseLogin = user.getUsername().toLowerCase();
            throw new UserNotActivatedException("User " + lowercaseLogin + " was not activated");
        }
        return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
                user.isCredentialsNonExpired(), user.isAccountNonLocked(), authorities);
    }
}
