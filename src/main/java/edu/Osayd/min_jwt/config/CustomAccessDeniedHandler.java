package edu.Osayd.min_jwt.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.PrintWriter;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    /*
    Purpose: Custom handler for 403 Forbidden responses.
    Key Functions:
        -Overrides the default Spring error with a JSON response.
    Security Role:
        -Improves UX when users are authenticated but not authorized (wrong roles, etc.).
        -Helps during debugging.
     */
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");

        PrintWriter out = response.getWriter();
        out.print("""
            {
              "error": "Access Denied",
              "message": "You do not have permission to access this resource."
            }
        """);
        out.flush();
    }
}
