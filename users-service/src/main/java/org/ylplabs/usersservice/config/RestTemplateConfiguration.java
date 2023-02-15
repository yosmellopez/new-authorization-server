package org.ylplabs.usersservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Component
public class RestTemplateConfiguration {

    @Bean
    @Qualifier("restTemplate")
    public RestTemplate restTemplate(RestTemplateBuilder restTemplateBuilder) {
        return restTemplateBuilder
                .setReadTimeout(Duration.ofMinutes(10))
                .setConnectTimeout(Duration.ofMinutes(10))
                .build();
    }
}
