package edu.Osayd.min_jwt.config;

import edu.Osayd.min_jwt.filter.JwtAuthenticationFilter;
import edu.Osayd.min_jwt.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    /*
    Purpose: Central security configuration for the application.
        Key Functions:
            -Defines a SecurityFilterChain that:
                -Disables CSRF (since the app is stateless).
                -Marks /api2/login and /api2/public as public (no auth required).
                -Requires authentication for all other endpoints.
                -Inserts a custom JWT filter before Spring's UsernamePasswordAuthenticationFilter.
                -Sets the app to stateless session policy (ideal for JWT).

            -Registers beans for:
                -JwtAuthenticationFilter (constructed with dependencies).
                -AuthenticationManager.
                -PasswordEncoder (BCrypt).
                -UserDetailsService with an in-memory user.

        Security Role:
            -Core configuration of authentication and authorization.
            -Integrates the JWT filter to enforce token validation.
            -Wires in a custom access denied handler for cleaner error responses.
     */

    private final CustomAccessDeniedHandler accessDeniedHandler;

    @Autowired
    public SecurityConfig(CustomAccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil,
                                                           UserDetailsService userDetailsService) {
        return new JwtAuthenticationFilter(jwtUtil, userDetailsService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api2/login", "/api2/public").permitAll()
                        .requestMatchers("/api2/admin").hasRole("ADMIN")
                        .requestMatchers("/api2/user").hasRole("USER")
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(ex -> ex.accessDeniedHandler(accessDeniedHandler))
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(User.withUsername("user")
                .password(passwordEncoder().encode("user123")) // or pre-encoded
                .roles("USER")
                .build());

        manager.createUser(User.withUsername("admin")
                .password(passwordEncoder().encode("admin123")) // or pre-encoded
                .roles("ADMIN")
                .build());

        return manager;


    }

}