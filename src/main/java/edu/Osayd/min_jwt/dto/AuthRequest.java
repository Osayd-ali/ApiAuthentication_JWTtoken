package edu.Osayd.min_jwt.dto;

public class AuthRequest {

    /*
    Purpose: DTO used to represent login form data.
        Key Functions: Contains username and password fields.

        Security Role:
            -Carries user credentials to the backend in a structured, secure way.
     */
    private String username;
    private String password;

    // getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
