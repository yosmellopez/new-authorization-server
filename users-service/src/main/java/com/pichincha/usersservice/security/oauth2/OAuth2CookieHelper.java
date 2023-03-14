package com.pichincha.usersservice.security.oauth2;

import com.nimbusds.jose.util.Base64;
import com.pichincha.usersservice.config.oauth2.OAuth2Properties;
import com.pichincha.usersservice.security.SecurityUtils;
import com.pichincha.usersservice.service.dto.OAuth2AccessToken;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Map;

public class OAuth2CookieHelper {

    /**
     * Name of the access token cookie.
     */
    public static final String ACCESS_TOKEN_COOKIE = "access_token";

    /**
     * Name of the refresh token cookie in case of remember me.
     */
    public static final String REFRESH_TOKEN_COOKIE = "refresh_token";

    /**
     * Name of the session-only refresh token in case the user did not check remember me.
     */
    public static final String SESSION_TOKEN_COOKIE = "session_token";

    /**
     * Number of seconds to expire refresh token cookies before the enclosed token expires.
     * This makes sure we don't run into race conditions where the cookie is still there but
     * expires while we process it.
     */
    private static final long REFRESH_TOKEN_EXPIRATION_WINDOW_SECS = 3L;

    private static final Logger log = LoggerFactory.getLogger(OAuth2CookieHelper.class);

    private final OAuth2Properties oAuth2Properties;

    /**
     * Used to parse JWT claims.
     */
    private final JsonParser jsonParser = JsonParserFactory.getJsonParser();

    public OAuth2CookieHelper(OAuth2Properties oAuth2Properties) {
        this.oAuth2Properties = oAuth2Properties;
    }


    /**
     * Create cookies using the provided values.
     *
     * @param request     the request we are handling.
     * @param accessToken the access token and enclosed refresh token for our cookies.
     * @param rememberMe  whether the user had originally checked "remember me".
     * @param result      will get the resulting cookies set.
     */
    public void createCookies(HttpServletRequest request, OAuth2AccessToken accessToken, boolean rememberMe, OAuth2Cookies result) {
        String domain = getCookieDomain(request);
        log.debug("creating cookies for domain {}", domain);
        Cookie accessTokenCookie = new Cookie(ACCESS_TOKEN_COOKIE, accessToken.getAccessToken());
        setCookieProperties(accessTokenCookie, request.isSecure(), domain);
        log.debug("created access token cookie '{}'", accessTokenCookie.getName());
        Instant now = Instant.now();
        Instant issuedAt = now.plusSeconds(accessToken.getExpiresIn());
        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(accessToken.getRefreshToken(), issuedAt);
        Cookie refreshTokenCookie = createRefreshTokenCookie(refreshToken, rememberMe);
        setCookieProperties(refreshTokenCookie, request.isSecure(), domain);
        log.debug("created refresh token cookie '{}', age: {}", refreshTokenCookie.getName(), refreshTokenCookie.getMaxAge());

        result.setCookies(accessTokenCookie, refreshTokenCookie);
    }

    /**
     * Create a cookie out of the given refresh token.
     * Refresh token cookies contain the base64 encoded refresh token (a JWT token).
     * They also contain a hint whether the refresh token was for remember me or not.
     * If not, then the cookie will be prefixed by the timestamp it was created at followed by a pipe '|'.
     * This gives us the chance to expire session cookies regardless of the token duration.
     */
    private Cookie createRefreshTokenCookie(OAuth2RefreshToken refreshToken, boolean rememberMe) {
        int maxAge = -1;
        String name = SESSION_TOKEN_COOKIE;
        String value = refreshToken.getTokenValue();
        if (rememberMe) {
            name = REFRESH_TOKEN_COOKIE;
            //get expiration in seconds from the token's "exp" claim
            Integer exp = getClaim(refreshToken.getTokenValue(), "EXP", Integer.class);
            if (exp != null) {
                int now = (int) (System.currentTimeMillis() / 1000L);
                maxAge = exp - now;
                log.debug("refresh token valid for another {} secs", maxAge);
                //let cookie expire a bit earlier than the token to avoid race conditions
                maxAge -= REFRESH_TOKEN_EXPIRATION_WINDOW_SECS;
            }
        }
        Cookie refreshTokenCookie = new Cookie(name, value);
        refreshTokenCookie.setMaxAge(maxAge);
        return refreshTokenCookie;
    }

    /**
     * Retrieve the given claim from the given token.
     *
     * @param refreshToken the JWT token to examine.
     * @param claimName    name of the claim to get.
     * @param clazz        the {@link Class} we expect to find there.
     * @return the desired claim.
     */
    @SuppressWarnings("unchecked")
    private <T> T getClaim(String refreshToken, String claimName, Class<T> clazz) {
        JwtDecoder jwtDecoder = NimbusJwtDecoder.withSecretKey(getSecretKey())
                .macAlgorithm(SecurityUtils.JWT_ALGORITHM)
                .build();
        Jwt jwt = jwtDecoder.decode(refreshToken);
        Map<String, Object> claimsMap = jwt.getClaims();
        Object claimValue = claimsMap.get(claimName);
        if (claimValue == null) {
            return null;
        }
        if (!clazz.isAssignableFrom(claimValue.getClass())) {
            throw new InvalidBearerTokenException("claim is not of expected type: " + claimName);
        }
        return (T) claimValue;
    }

    private SecretKey getSecretKey() {
        byte[] keyBytes = Base64.from("").decode();
        return new SecretKeySpec(keyBytes, 0, keyBytes.length, SecurityUtils.JWT_ALGORITHM.getName());
    }

    /**
     * Set cookie properties of access and refresh tokens.
     *
     * @param cookie   the cookie to modify.
     * @param isSecure whether it is coming from a secure request.
     * @param domain   the domain for which the cookie is valid. If {@code null}, then will fall back to default.
     */
    private void setCookieProperties(Cookie cookie, boolean isSecure, String domain) {
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setSecure(isSecure);       //if the request comes per HTTPS set the secure option on the cookie
        if (domain != null) {
            cookie.setDomain(domain);
        }
    }

    /**
     * Returns the top level domain of the server from the request. This is used to limit the Cookie
     * to the top domain instead of the full domain name.
     * <p>
     * A lot of times, individual gateways of the same domain get their own subdomain but authentication
     * shall work across all subdomains of the top level domain.
     * <p>
     * For example, when sending a request to {@code app1.domain.com},
     * this returns {@code .domain.com}.
     *
     * @param request the HTTP request we received from the client.
     * @return the top level domain to set the cookies for.
     * Returns {@code null} if the domain is not under a public suffix (.com, .co.uk), e.g. for localhost.
     */
    private String getCookieDomain(HttpServletRequest request) {
        String domain = oAuth2Properties.getWebClientConfiguration().getCookieDomain();
        if (domain != null) {
            return domain;
        }
        // if not explicitly defined, use top-level domain
        domain = request.getServerName().toLowerCase();
        // strip off leading www.
        if (domain.startsWith("www.")) {
            domain = domain.substring(4);
        }
        // no top-level domain, stick with default domain
        return domain;
    }

}
