package org.ylplabs.usersservice.service.dto;

public final class OAuthCsrfToken {

    private String token;

    private String parameterName;

    private String headerName;

    public OAuthCsrfToken() {
    }

    public String getHeaderName() {
        return this.headerName;
    }

    public String getParameterName() {
        return this.parameterName;
    }

    public String getToken() {
        return this.token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setParameterName(String parameterName) {
        this.parameterName = parameterName;
    }

    public void setHeaderName(String headerName) {
        this.headerName = headerName;
    }
}
