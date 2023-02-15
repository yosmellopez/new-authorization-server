package org.ylplabs.usersservice.web.rest.vm;

public class QRResponse {

    private String qrCode;

    private String token;

    public QRResponse() {
    }

    public QRResponse(String qrCode) {
        this.qrCode = qrCode;
    }

    public QRResponse(String qrCode, String token) {
        this.qrCode = qrCode;
        this.token = token;
    }

    public String getQrCode() {
        return qrCode;
    }

    public void setQrCode(String qrCode) {
        this.qrCode = qrCode;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
