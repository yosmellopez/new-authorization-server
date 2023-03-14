package com.pichincha.usersservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties {

    private String bitcoinBaseUrl;

    private String bitcoinVersion;

    private String bitcoinPath;

    private Long bitcoinHistoryCount;

    private String uploadDirectory;

    private String name;

    private String personal;

    private String coinpaymentService;

    private String coinpaymentPort;

    private String validatorService;

    private String validatorPort;

    private String baseUrl;

    private Boolean localDeployment = false;

    private Coinpayment coinpayment;

    private Sms sms;

    private Gmail gmail;

    public String getBitcoinBaseUrl() {
        return bitcoinBaseUrl;
    }

    public void setBitcoinBaseUrl(String bitcoinBaseUrl) {
        this.bitcoinBaseUrl = bitcoinBaseUrl;
    }

    public String getBitcoinVersion() {
        return bitcoinVersion;
    }

    public void setBitcoinVersion(String bitcoinVersion) {
        this.bitcoinVersion = bitcoinVersion;
    }

    public String getBitcoinPath() {
        return bitcoinPath;
    }

    public void setBitcoinPath(String bitcoinPath) {
        this.bitcoinPath = bitcoinPath;
    }

    public Long getBitcoinHistoryCount() {
        return bitcoinHistoryCount;
    }

    public void setBitcoinHistoryCount(Long bitcoinHistoryCount) {
        this.bitcoinHistoryCount = bitcoinHistoryCount;
    }

    public String getUploadDirectory() {
        return uploadDirectory;
    }

    public void setUploadDirectory(String uploadDirectory) {
        this.uploadDirectory = uploadDirectory;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPersonal() {
        return personal;
    }

    public void setPersonal(String personal) {
        this.personal = personal;
    }

    public Boolean getLocalDeployment() {
        return localDeployment;
    }

    public void setLocalDeployment(Boolean localDeployment) {
        this.localDeployment = localDeployment;
    }

    public String getCoinpaymentService() {
        return coinpaymentService;
    }

    public void setCoinpaymentService(String coinpaymentService) {
        this.coinpaymentService = coinpaymentService;
    }

    public String getCoinpaymentPort() {
        return coinpaymentPort;
    }

    public void setCoinpaymentPort(String coinpaymentPort) {
        this.coinpaymentPort = coinpaymentPort;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Coinpayment getCoinpayment() {
        return coinpayment;
    }

    public void setCoinpayment(Coinpayment coinpayment) {
        this.coinpayment = coinpayment;
    }

    public Sms getSms() {
        return sms;
    }

    public void setSms(Sms sms) {
        this.sms = sms;
    }

    public Gmail getGmail() {
        return gmail;
    }

    public void setGmail(Gmail gmail) {
        this.gmail = gmail;
    }

    public String getValidatorService() {
        return validatorService;
    }

    public void setValidatorService(String validatorService) {
        this.validatorService = validatorService;
    }

    public String getValidatorPort() {
        return validatorPort;
    }

    public void setValidatorPort(String validatorPort) {
        this.validatorPort = validatorPort;
    }

    public static class Coinpayment {

        private String ipnSecret;

        public String getIpnSecret() {
            return ipnSecret;
        }

        public void setIpnSecret(String ipnSecret) {
            this.ipnSecret = ipnSecret;
        }
    }

    public static class Sms {

        private String apiKey;

        private String apiSecret;

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getApiSecret() {
            return apiSecret;
        }

        public void setApiSecret(String apiSecret) {
            this.apiSecret = apiSecret;
        }
    }

    public static class Gmail {

        private String userEmail;

        private String clientId;

        private String clientSecret;

        private String accessToken;

        private String refreshToken;

        public String getUserEmail() {
            return userEmail;
        }

        public void setUserEmail(String userEmail) {
            this.userEmail = userEmail;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }
    }
}
