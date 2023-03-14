package com.pichincha.usersservice.web.rest.errors;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OauthErrorMapping {

    private String error;

    @JsonProperty("error_description")
    private String errorDescription;

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }
}
