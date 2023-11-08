package io.basic.security.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
@Configuration
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        RequestCache lastCache = new HttpSessionRequestCache();
        SavedRequest savedRequest = lastCache.getRequest(request, response);
        if (savedRequest == null){
            System.out.println("authentication is succeeded, name: " + authentication.getName());
            response.sendRedirect("/");
        } else {
            System.out.println("authentication is succeeded, move to last request");
            response.sendRedirect(savedRequest.getRedirectUrl());
        }

    }
}
