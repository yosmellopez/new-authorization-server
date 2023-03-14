package com.pichincha.usersservice.security.oauth2;

public enum GrantTypes {
    PASSWORD("password"), MFA("mfa"), QR_CODE_AUTH("qr_code_auth"), LOCAL_AUTH("local_auth"), UNLOCK_SESSION("unlock_session");

    private final String type;

    GrantTypes(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
