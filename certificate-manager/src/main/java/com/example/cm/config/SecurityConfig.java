package com.example.cm.config;

import com.example.cm.model.entity.UserEntity;
import com.example.cm.repository.UserRepository;
import com.example.cm.service.AuditService;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuditService auditService;

    public SecurityConfig(AuditService auditService) {
        this.auditService = auditService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> auth
                        // public endpoints: OCSP responder + CRL distribution points
                        .requestMatchers(HttpMethod.POST, "/api/ocsp").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/ocsp/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/crl/**").permitAll()
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
                        // CA management is admin-only; the active-CA list stays readable by any
                        // authenticated user because it powers the CSR issuer / CRL dropdowns
                        .requestMatchers(HttpMethod.GET, "/api/ca/active").authenticated()
                        .requestMatchers("/api/ca", "/api/ca/**").hasRole("ADMIN")
                        // certificate profiles: any authenticated user can read (requester
                        // picks a profile), only admin can create/update/delete
                        .requestMatchers(HttpMethod.GET, "/api/profiles", "/api/profiles/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/profiles", "/api/profiles/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/profiles/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/profiles/**").hasRole("ADMIN")
                        // CRL generation is admin-only (CRLs refresh automatically on revoke)
                        .requestMatchers(HttpMethod.POST, "/api/crl/**").hasRole("ADMIN")
                        // certificate lifecycle operations are admin-only
                        .requestMatchers(HttpMethod.POST, "/api/certificates/*/revoke", "/api/certificates/*/suspend",
                                "/api/certificates/*/resume").hasRole("ADMIN")
                        // certificate requests (CSR or manual) any authenticated role
                        .requestMatchers(HttpMethod.POST, "/api/certificates/csr", "/api/certificates/request")
                        .hasAnyRole("REQUESTER", "ADMIN")
                        // signed audit trail is admin-only
                        .requestMatchers("/api/audit", "/api/audit/**").hasRole("ADMIN")
                        // user management is admin-only
                        .requestMatchers("/api/users", "/api/users/**").hasRole("ADMIN")
                        // admin-only operations
                        .requestMatchers(HttpMethod.DELETE, "/api/**").hasRole("ADMIN")
                        .requestMatchers("/api/pkcs11/**").hasRole("ADMIN")
                        // UI and static resources require authentication
                        .requestMatchers("/", "/index.html", "/css/**", "/js/**").permitAll()
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex.authenticationEntryPoint(auditEntryPoint()))
                .headers(headers -> headers.frameOptions(f -> f.disable()))
                .httpBasic(basic -> basic.authenticationEntryPoint(auditEntryPoint()))
                .formLogin(fl -> fl.defaultSuccessUrl("/", true));
        return http.build();
    }

    /**
     * Entry point used for every failed HTTP Basic authentication (both the
     * {@code httpBasic} filter and the exception-handling filter for unauthenticated
     * access). Records the failed login in the signed audit log unless this is the
     * forwarded {@code /error} dispatch produced by the 401 itself, which would
     * otherwise loop and spam the log with anonymous entries.
     */
    private AuthenticationEntryPoint auditEntryPoint() {
        return (request, response, authException) -> {
            if (DispatcherType.ERROR != request.getDispatcherType()) {
                auditService.record(basicUsername(request), "AUTH", "LOGIN_FAILED",
                        "path=" + request.getRequestURI() + ", remote=" + remoteAddress(request));
            }
            response.sendError(401, "Unauthorized");
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> {
            UserEntity user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
            return User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .roles(user.getRoles().toArray(new String[0]))
                    .disabled(!user.isEnabled())
                    .build();
        };
    }

    private String basicUsername(HttpServletRequest request) {
        try {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Basic ")) {
                String decoded = new String(Base64.getDecoder()
                        .decode(header.substring(6)), StandardCharsets.UTF_8);
                int colon = decoded.indexOf(':');
                if (colon > 0) {
                    return decoded.substring(0, colon);
                }
            }
        } catch (Exception ignored) {
            // fall through
        }
        return "anonymous";
    }

    private String remoteAddress(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return forwarded != null && !forwarded.isBlank() ? forwarded.trim() : request.getRemoteAddr();
    }
}
