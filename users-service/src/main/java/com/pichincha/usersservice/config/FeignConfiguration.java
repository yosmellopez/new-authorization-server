package com.pichincha.usersservice.config;


import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClientsConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableFeignClients(basePackages = {"com.pichincha.usersservice.service.client",
        "com.pichincha.usersservice.security.client"})
@Import(FeignClientsConfiguration.class)
public class FeignConfiguration {

}
