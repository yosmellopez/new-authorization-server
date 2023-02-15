package org.ylplabs.usersservice.web.rest.vm;

import java.math.BigDecimal;

public class TransferTransaction {

    private BigDecimal amount;

    private String walletAddress;

    private Integer twoFactorCode;

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
    }

    public String getWalletAddress() {
        return walletAddress;
    }

    public void setWalletAddress(String walletAddress) {
        this.walletAddress = walletAddress;
    }

    public Integer getTwoFactorCode() {
        return twoFactorCode;
    }

    public void setTwoFactorCode(Integer twoFactorCode) {
        this.twoFactorCode = twoFactorCode;
    }

    @Override
    public String toString() {
        return ("TransferTransaction{" + "amount=" + amount + ", walletAddress='" + walletAddress + '\'' + ", twoFactorCode='" + twoFactorCode + '\'' + '}');
    }
}
