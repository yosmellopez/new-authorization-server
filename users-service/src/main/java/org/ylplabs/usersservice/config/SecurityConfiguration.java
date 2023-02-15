package org.ylplabs.usersservice.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.ylplabs.usersservice.config.oauth2.OAuth2Properties;
import org.ylplabs.usersservice.security.oauth2.JpaOAuth2ClientAuthorizationService;
import org.ylplabs.usersservice.security.oauth2.JwtGrantedAuthorityConverter;
import org.ylplabs.usersservice.security.oauth2.OAuth2CookieHelper;
import org.ylplabs.usersservice.security.oauth2.OAuth2SecurityAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Value("${spring.security.oauth2.client.provider.oauth-web-client.issuer-uri}")
    private String issuerUri;
    private final OAuth2Properties oAuth2Properties;
    private final JpaOAuth2ClientAuthorizationService authorizationService;
    private final OAuth2SecurityAuthenticationEntryPoint authenticationEntryPoint;

    public SecurityConfiguration(OAuth2Properties oAuth2Properties, JpaOAuth2ClientAuthorizationService authorizationService,
                                 OAuth2SecurityAuthenticationEntryPoint authenticationEntryPoint) {
        this.oAuth2Properties = oAuth2Properties;
        this.authorizationService = authorizationService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
//            .csrf(csrf -> csrf
//                .ignoringRequestMatchers("/api/authenticate")
//                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .exceptionHandling(configurer -> configurer.authenticationEntryPoint(authenticationEntryPoint))
                .headers()
                .referrerPolicy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                .permissionsPolicy().policy("camera=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), sync-xhr=()")
                .and()
                .frameOptions().sameOrigin()
                .and()
                .authorizeHttpRequests()
                .requestMatchers(HttpMethod.POST, "/api/qr-code-authentication", "/api/local-authentication").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/swagger-ui/**").permitAll()
                .requestMatchers("/api/authenticate", "/api/two-factor-authentication", "/api/register", "/api/token-auth", "/api/qr-code-auth", "/api/qr-code-auth/**").permitAll()
                .requestMatchers("/api/authenticate/test", "/api/parent/*").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/provinces-all", "/api/countries-all", "/api/provinces-country/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/callback/**", "/api/qr-code-authentication", "/api/local-authentication", "/api/logout").permitAll()
                .requestMatchers("/api/countries", "/api/search-countries").permitAll()
                .requestMatchers("/api/document-types", "/api/check-email", "/api/check-username", "/api/test-geolocalization", "/api/validate-phone", "/api/check-telephone").permitAll()
                .requestMatchers("/api/coinpayment/**").permitAll()
                .requestMatchers("/api/resource/image/**", "/api/exist/resource/image/**", "/api/resource/img/**", "/resource/image/default").permitAll()
                .requestMatchers("/api/generate/**").permitAll()
                .requestMatchers("/api/activate").permitAll()
                .requestMatchers("/api/account/reset-password/init").permitAll()
                .requestMatchers("/api/account/reset-password/finish").permitAll()
                .requestMatchers("/api/**").authenticated()
                .requestMatchers("/websocket/mobile").authenticated()
                .requestMatchers("/websocket/login").permitAll()
                .requestMatchers("/management/health").permitAll()
                .requestMatchers("/management/health/**").permitAll()
                .requestMatchers("/management/info").permitAll()
                .requestMatchers("/management/prometheus").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout(configurer -> configurer.logoutUrl("/api/logout")
                        .deleteCookies("session_token", "access_token")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                        }))
                .oauth2Login(configurer -> configurer
                        .loginProcessingUrl("/oauth2/authenticate")
                        .successHandler((request, response, authentication) -> response.setStatus(HttpServletResponse.SC_OK))
                        .failureHandler((request, response, exception) -> response.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
                        .authorizedClientService(authorizationService))
                .oauth2Client(configurer -> configurer
                        .authorizedClientService(authorizationService))
                .oauth2ResourceServer(configurer -> configurer
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler((request, response, accessDeniedException) -> response.setStatus(HttpServletResponse.SC_UNAUTHORIZED))
                        .jwt()
                        .jwtAuthenticationConverter(authenticationConverter()));
        return http.build();
        // @formatter:on
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2CookieHelper oAuth2CookieHelper() {
        return new OAuth2CookieHelper(oAuth2Properties);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuerUri);
//        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(jHipsterProperties.getSecurity().getOauth2().getAudience());
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer);
        jwtDecoder.setJwtValidator(withAudience);
        return jwtDecoder;
    }

    private Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtGrantedAuthorityConverter());
        return jwtAuthenticationConverter;
    }
}
