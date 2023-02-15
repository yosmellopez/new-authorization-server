package org.ylplabs.usersservice.service;

import java.io.Serial;

public class UsernameAlreadyUsedException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    public UsernameAlreadyUsedException() {
        super("Login name already used!");
    }
}
