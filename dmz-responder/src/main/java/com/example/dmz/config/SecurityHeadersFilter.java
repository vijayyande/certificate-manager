package com.example.dmz.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Hardening headers for a public-facing responder. The app serves no HTML, so a
 * restrictive default CSP and clickjacking/framing protection are appropriate.
 */
@Component
@Order(Integer.MIN_VALUE)
public class SecurityHeadersFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletResponse http = (HttpServletResponse) response;
        http.setHeader("X-Content-Type-Options", "nosniff");
        http.setHeader("X-Frame-Options", "DENY");
        http.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        http.setHeader("Referrer-Policy", "no-referrer");
        chain.doFilter(request, response);
    }
}
