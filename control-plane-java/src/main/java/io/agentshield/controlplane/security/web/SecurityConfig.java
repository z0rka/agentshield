package io.agentshield.controlplane.security.web;

import io.agentshield.controlplane.security.domain.Role;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * HTTP security.
 *
 * <p>Deny by default: every path not explicitly permitted requires authentication, so adding
 * a controller cannot accidentally publish an endpoint. Sessions are stateless - the API is
 * consumed by CLIs and CI jobs, and a session cookie would only be a CSRF surface.
 *
 * <p>CSRF is disabled, and only because there are no cookies to forge with. Reintroducing
 * cookie authentication for the web UI means reintroducing CSRF protection in the same change.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(
            HttpSecurity http,
            ApiAuthenticationFilter authenticationFilter,
            RateLimitFilter rateLimitFilter)
            throws Exception {
        return http.csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(handling ->
                        handling.authenticationEntryPoint(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // After authentication, so the bucket is per principal. Before the
                // controllers, so a caller over the ceiling costs one 429 and no database
                // connection.
                .addFilterAfter(rateLimitFilter, ApiAuthenticationFilter.class)
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        // The controller performs constant-time shared-token authentication.
                        .requestMatchers("/internal/engine/**").permitAll()
                        .requestMatchers("/actuator/**").hasAuthority(Role.OWNER.authority())
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll())
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // Cost 12: roughly 250ms per verification on current hardware, which is the point.
        return new BCryptPasswordEncoder(12);
    }
}
