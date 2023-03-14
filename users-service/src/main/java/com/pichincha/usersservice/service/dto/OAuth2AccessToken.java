package com.pichincha.usersservice.service.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuth2AccessToken {
    private String accessToken;
    private String refreshToken;
    private String scope;
    private String idToken;
    private String tokenType;
    private long expiresIn;

    @JsonProperty("access_token")
    public String getAccessToken() {
        return accessToken;
    }

    @JsonProperty("access_token")
    public void setAccessToken(String value) {
        this.accessToken = value;
    }

    @JsonProperty("refresh_token")
    public String getRefreshToken() {
        return refreshToken;
    }

    @JsonProperty("refresh_token")
    public void setRefreshToken(String value) {
        this.refreshToken = value;
    }

    @JsonProperty("scope")
    public String getScope() {
        return scope;
    }

    @JsonProperty("scope")
    public void setScope(String value) {
        this.scope = value;
    }

    @JsonIgnore
    @JsonProperty("id_token")
    public String getIDToken() {
        return idToken;
    }

    @JsonProperty("id_token")
    public void setIDToken(String value) {
        this.idToken = value;
    }

    @JsonProperty("token_type")
    public String getTokenType() {
        return tokenType;
    }

    @JsonProperty("token_type")
    public void setTokenType(String value) {
        this.tokenType = value;
    }

    @JsonProperty("expires_in")
    public long getExpiresIn() {
        return expiresIn;
    }

    @JsonProperty("expires_in")
    public void setExpiresIn(long value) {
        this.expiresIn = value;
    }
}
