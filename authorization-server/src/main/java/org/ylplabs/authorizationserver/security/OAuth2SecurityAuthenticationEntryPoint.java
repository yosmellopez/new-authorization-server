package org.ylplabs.authorizationserver.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final Logger log = LoggerFactory.getLogger(OAuth2SecurityAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        log.error("Ocurrio un error en la autenticacion del usuario", authException);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
