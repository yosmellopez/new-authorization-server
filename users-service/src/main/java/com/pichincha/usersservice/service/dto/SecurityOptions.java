package com.pichincha.usersservice.service.dto;

import jakarta.validation.constraints.NotNull;

public class SecurityOptions {

    @NotNull
    private Boolean isUsing2FA;

    @NotNull
    private Boolean askPasswordChange;

    private Integer code;

    public Boolean getUsing2FA() {
        return isUsing2FA;
    }

    public void setUsing2FA(Boolean using2FA) {
        isUsing2FA = using2FA;
    }

    public Boolean getAskPasswordChange() {
        return askPasswordChange;
    }

    public void setAskPasswordChange(Boolean askPasswordChange) {
        this.askPasswordChange = askPasswordChange;
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }
}
