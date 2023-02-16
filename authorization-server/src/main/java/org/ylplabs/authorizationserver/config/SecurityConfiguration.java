package org.ylplabs.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OidcConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.ylplabs.authorizationserver.security.LoginAuthenticationFailureHandler;
import org.ylplabs.authorizationserver.security.LoginAuthenticationSuccessHandler;
import org.ylplabs.authorizationserver.security.OAuth2AuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
public class SecurityConfiguration {

    private final OAuth2AuthenticationEntryPoint entryPoint;
    private final LoginAuthenticationSuccessHandler authenticationSuccessHandler;
    private final LoginAuthenticationFailureHandler loginAuthenticationFailureHandler;
    private final UserDetailsService userDetailsService;

    public SecurityConfiguration(OAuth2AuthenticationEntryPoint entryPoint,
                                 LoginAuthenticationSuccessHandler authenticationSuccessHandler,
                                 LoginAuthenticationFailureHandler loginAuthenticationFailureHandler, UserDetailsService userDetailsService) {
        this.entryPoint = entryPoint;
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        this.loginAuthenticationFailureHandler = loginAuthenticationFailureHandler;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    @Order(2)
    public SecurityFilterChain serverSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.exceptionHandling()
                .authenticationEntryPoint(entryPoint)
                .and()
                .csrf()
                .disable()
                .headers()
                .frameOptions()
                .disable()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .userDetailsService(userDetailsService)
                .authorizeHttpRequests()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/v1/oauth2/authorize", "/v1/oauth2/keys").permitAll()
                .requestMatchers("/api/activate", "/oauth/login").permitAll()
                .requestMatchers("/api/authenticate", "/api/two-factor-authentication").permitAll()
                .requestMatchers("/api/account/reset-password/init").permitAll()
                .requestMatchers("/api/account/reset-password/finish").permitAll()
                .requestMatchers("/management/health").permitAll()
                .requestMatchers("/api/authenticate", "/api/register", "/api/token-auth", "/api/qr-code-auth", "/api/qr-code-auth/**").permitAll()
                .requestMatchers("/api/parent/*").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/provinces-all", "/api/countries-all", "/api/provinces-country/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/callback/**", "/api/qr-code-authentication", "/api/local-authentication").permitAll()
                .requestMatchers(HttpMethod.PUT, "/api/account").permitAll()
                .requestMatchers("/api/countries", "/api/search-countries").permitAll()
                .requestMatchers("/api/document-types", "/api/check-email", "/api/check-username", "/api/test-geolocalization").permitAll()
                .requestMatchers("/api/coinpayment/**").permitAll()
                .requestMatchers("/api/resource/image/**", "/api/exist/resource/image/**", "/api/resource/img/**", "/resource/image/default").permitAll()
                .requestMatchers("/api/generate/**").permitAll()
                .requestMatchers("/websocket/login").permitAll()
                .requestMatchers("/management/health").permitAll()
                .requestMatchers("/management/health/**").permitAll()
                .requestMatchers("/management/info").permitAll()
                .requestMatchers("/management/prometheus").permitAll()
                .requestMatchers("/websocket/mobile").authenticated()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll()
                .and()
                .build();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        Customizer<OidcConfigurer> oidcConfigCustomizer = customizer -> customizer
                .clientRegistrationEndpoint(Customizer.withDefaults());

        authorizationServerConfigurer.oidc(oidcConfigCustomizer);
        RequestMatcher endpointsMatcher = authorizationServerConfigurer
                .getEndpointsMatcher();

        authorizationServerConfigurer.authorizationEndpoint(configurer -> configurer
                .authorizationResponseHandler(authenticationSuccessHandler)
                .errorResponseHandler(loginAuthenticationFailureHandler));

        authorizationServerConfigurer.tokenEndpoint(configurer -> configurer.errorResponseHandler(loginAuthenticationFailureHandler));

        AntPathRequestMatcher loginAntMatcher = AntPathRequestMatcher.antMatcher("/v1/oauth2/login");
        AntPathRequestMatcher authenticateAntMatcher = AntPathRequestMatcher.antMatcher("/v1/oauth2/authenticate");
        AntPathRequestMatcher resetPasswordMatcher = AntPathRequestMatcher.antMatcher(HttpMethod.PUT, "/api/account");
        AntPathRequestMatcher h2ConsoleMatcher = AntPathRequestMatcher.antMatcher("/h2-console/**");

        final OrRequestMatcher requestMatcher = new OrRequestMatcher(endpointsMatcher, loginAntMatcher, authenticateAntMatcher, resetPasswordMatcher, h2ConsoleMatcher);

        http.authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/v1/oauth2/authenticate").permitAll()
                                .requestMatchers("/v1/oauth2/login").permitAll()
                                .requestMatchers("/h2-console/**").permitAll()
                                .requestMatchers(HttpMethod.PUT, "/api/account").permitAll()
                                .anyRequest().authenticated())
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .csrf(csrf -> csrf.ignoringRequestMatchers(requestMatcher))
                .formLogin(loginConfigurer -> loginConfigurer.loginPage("/v1/oauth2/login")
                        .loginProcessingUrl("/v1/oauth2/authenticate")
                        .successHandler(authenticationSuccessHandler)
                        .failureHandler(loginAuthenticationFailureHandler))
                .apply(authorizationServerConfigurer);
        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource, OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
        JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
        JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
        jwtGenerator.setJwtCustomizer(jwtCustomizer);
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
        return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8081")
                .tokenEndpoint("/v1/oauth2/token")
                .authorizationEndpoint("/v1/oauth2/authorize")
                .tokenEndpoint("/v1/oauth2/token")
                .jwkSetEndpoint("/v1/oauth2/jwks")
                .tokenRevocationEndpoint("/v1/oauth2/revoke")
                .tokenIntrospectionEndpoint("/v1/oauth2/introspect")
                .oidcClientRegistrationEndpoint("/v1/connect/register")
                .oidcUserInfoEndpoint("/v1/oauth2/userinfo")
                .build();
    }
}
