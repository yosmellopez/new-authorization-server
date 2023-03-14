package com.pichincha.usersservice.security.oauth2;

import com.pichincha.usersservice.web.rest.errors.UnauthorizedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;

@Component
public class OAuth2SecurityAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final Logger log = LoggerFactory.getLogger(OAuth2SecurityAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        log.error("Ocurrio un error en la autenticacion del usuario", authException);
        if (authException instanceof InvalidBearerTokenException) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            throw new UnauthorizedException(URI.create("/no-authorized"), "Error de Authorizacion");
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
