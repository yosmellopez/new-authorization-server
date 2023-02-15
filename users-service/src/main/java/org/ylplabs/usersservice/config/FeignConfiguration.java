package org.ylplabs.usersservice.config;


import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClientsConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableFeignClients(basePackages = {"org.ylplabs.usersservice.service.client", "org.ylplabs.usersservice.security.client"})
@Import(FeignClientsConfiguration.class)
public class FeignConfiguration {

}
