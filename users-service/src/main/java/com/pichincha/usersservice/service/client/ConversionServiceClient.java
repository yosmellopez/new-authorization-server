package com.pichincha.usersservice.service.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import com.pichincha.usersservice.service.dto.CurrencyConversion;
import com.pichincha.usersservice.service.dto.ConversionResponse;

@FeignClient(value = "conversion-client",
        url = "http://localhost:3000",
        path = "/api",
        configuration = OAuth2FeignConfiguration.class)
public interface ConversionServiceClient {
    @PostMapping("/convert-currencies")
    ResponseEntity<ConversionResponse> convertCurrencies(@RequestBody CurrencyConversion currencyConversion);
}
