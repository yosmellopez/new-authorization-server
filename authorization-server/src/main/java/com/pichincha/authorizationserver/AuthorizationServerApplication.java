package com.pichincha.authorizationserver;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import com.pichincha.authorizationserver.security.RegisterClientService;

@SpringBootApplication
public class AuthorizationServerApplication implements CommandLineRunner {

    private final RegisterClientService service;

    public AuthorizationServerApplication(RegisterClientService service) {
        this.service = service;
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

    @Override
    public void run(String... args) {
        service.initialRegistration();
    }
}
