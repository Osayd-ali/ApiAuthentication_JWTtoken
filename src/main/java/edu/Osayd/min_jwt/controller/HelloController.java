package edu.Osayd.min_jwt.controller;

import edu.Osayd.min_jwt.dto.AuthRequest;
import edu.Osayd.min_jwt.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api2")
public class HelloController {

    /*
        Purpose: REST controller exposing three endpoints:
            -POST /api2/login — authenticates user and returns JWT.
            -GET /api2/admin & /api2/user — protected endpoint; requires a valid JWT.
            -GET /api2/public — public endpoint; does not require authentication.

        Key Functions:
            -Uses AuthenticationManager to validate credentials.
            -Delegates to JwtUtil to issue JWT tokens.

        Security Role:
            -Exposes login interface to trigger JWT authentication.
            -Demonstrates secured and public access paths.
     */
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public HelloController(AuthenticationManager authManager, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthRequest request) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword());
        authManager.authenticate(authentication);
        return jwtUtil.generateToken(authentication.getName());
    }

    @GetMapping("/admin") // Only an ADMIN role use this endpoint
    public String admin(@RequestBody AuthRequest request) {
        return "Hello, " + request.getUsername() + "! You are an admin.";
    }

    @GetMapping("/user") // Only an USER role use this endpoint
    public String user(@RequestBody AuthRequest request) {
        return "Hello, " + request.getUsername() + "! You are a user.";
    }

    @GetMapping("/public")
    public String publicEndpoint(@RequestBody AuthRequest request) {
        return "This is an unsecured endpoint and does NOT require a token!";
    }
}