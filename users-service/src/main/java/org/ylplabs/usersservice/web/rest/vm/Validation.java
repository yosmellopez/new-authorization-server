package org.ylplabs.usersservice.web.rest.vm;

public class Validation {

    private boolean valid;

    public Validation(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }
}
