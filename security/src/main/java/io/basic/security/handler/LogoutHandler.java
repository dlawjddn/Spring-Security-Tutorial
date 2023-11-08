package io.basic.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.IOException;
@Configuration
public class LogoutHandler implements org.springframework.security.web.authentication.logout.LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        HttpSession session = request.getSession();
        session.invalidate();
        try {
            response.sendRedirect("/login");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
