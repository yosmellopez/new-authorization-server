package com.pichincha.usersservice.security.oauth2;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * A request mapper used to modify the cookies in the original request.
 * This is needed such that we can modify the cookies of the request during a token refresh.
 * The token refresh happens before authentication by the {@code OAuth2AuthenticationProcessingFilter}
 * so we must make sure that further in the filter chain, we have the new cookies and not the expired/missing ones.
 */
class CookiesHttpServletRequestWrapper extends HttpServletRequestWrapper {

    /**
     * The new cookies of the request. Use these instead of the ones found in the wrapped request.
     */
    private final Cookie[] cookies;

    public CookiesHttpServletRequestWrapper(HttpServletRequest request, Cookie[] cookies) {
        super(request);
        this.cookies = cookies;
    }

    /**
     * Return the modified cookies instead of the original ones.
     *
     * @return the modified cookies.
     */
    @Override
    public Cookie[] getCookies() {
        return cookies;
    }
}
