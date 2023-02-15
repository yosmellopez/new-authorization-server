package org.ylplabs.usersservice.web.rest.vm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * View Model object for storing a user's credentials.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginVM {

    @NotNull
    @Size(min = 1, max = 1000)
    private String username;

    @NotNull
    @Size(min = 4, max = 1000)
    private String password;

    private boolean rememberMe;

    public LoginVM() {
    }

    public LoginVM(String username, String password, boolean rememberMe) {
        this.username = username;
        this.password = password;
        this.rememberMe = rememberMe;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isRememberMe() {
        return rememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }

    // prettier-ignore
    @Override
    public String toString() {
        return "LoginVM{" + "username='" + username + '\'' + ", rememberMe=" + rememberMe + '}';
    }
}
