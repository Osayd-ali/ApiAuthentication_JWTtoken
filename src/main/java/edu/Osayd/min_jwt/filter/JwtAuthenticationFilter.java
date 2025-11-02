package edu.Osayd.min_jwt.filter;

import edu.Osayd.min_jwt.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /*
    Purpose: Custom filter that intercepts each request to validate JWT.
        Key Functions:
            -Checks for Authorization: Bearer <token>.
            -Uses JwtUtil to extract and validate the token.
            -Rebuilds the Authentication object with roles from the token.
            -Stores the authenticated user in the SecurityContext.
            -Skips processing for public endpoints like /auth/login and /api/public.

        Security Role:
            -Core component of JWT-based authentication.
            -Ensures that secured endpoints can only be accessed with valid tokens.
     */
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Autowired
    public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Your existing filtering logic


        String path = request.getServletPath();
        if (path.startsWith("/api2/login") || path.startsWith("/api2/public")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String authHeader = request.getHeader("Authorization");

        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new IllegalStateException("Missing or malformed Authorization header");
            }

            String jwtToken = authHeader.substring(7);
            String username = jwtUtil.extractUsername(jwtToken);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtUtil.validateToken(jwtToken, userDetails.getUsername())) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    log.info("Successful JWT auth for user '{}' from IP {}", username, request.getRemoteAddr());
                }
            }

            filterChain.doFilter(request, response);

        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
            {
              "error": "Token Expired",
              "message": "Your session has expired. Please log in again."
            } """);
            log.warn("Expired token for user '{}' from IP {}", e.getClaims().getSubject(), request.getRemoteAddr());

        } catch (IllegalStateException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
            {
              "error": "Missing Token",
              "message": "You must be logged in to access this resource."
            } """);
            log.warn("Missing token attempt from IP {}: {}", request.getRemoteAddr(), e.getMessage());

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("""
            {
              "error": "Invalid Token",
              "message": "Your session is invalid or has been tampered with. Please log in again."
            } """);
            log.warn("Invalid token attempt from IP {}: {}", request.getRemoteAddr(), e.getMessage());

        }
    }


}
