package org.ylplabs.authorizationserver.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class LoginAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final Logger log = LoggerFactory.getLogger(LoginAuthenticationSuccessHandler.class);

    private final ObjectMapper objectMapper;

    public LoginAuthenticationSuccessHandler(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("Sending Authentication if is {}", authentication.getClass());
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
            OAuth2AuthorizationCode authorizationCode = token.getAuthorizationCode();
            response.getWriter().print(objectMapper.writeValueAsString(authorizationCode));
        }
        if (authentication instanceof OAuth2ClientAuthenticationToken token) {
            response.getWriter().print(objectMapper.writeValueAsString(token));
        }
    }
}
