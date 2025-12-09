package com.example.demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;

@Slf4j
@Controller
public class LoginController {

    @GetMapping(value = {"/auth/login"})
    public String login(Authentication authentication, HttpSession session) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/home"; // or whatever your post-login page is
        }
        return "auth/login";
    }

    @PostMapping("/customSuccessPage")
    public String customSuccessPage(Model model, Principal principal, HttpServletRequest request) {
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        model.addAttribute("username", principal.getName());
        model.addAttribute("ipAddress", ipAddress);
        model.addAttribute("userAgent", userAgent);
        return "dashboard";
    }

    /**
     * We should use Exception exception = (Exception) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
     * if you are handling the failure using .failureForwardUrl() in Spring Security.
     *
     * If you are using .failureUrl() (which performs a redirect),
     * you must use request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
     * because the redirect starts a new request.
     */
    @PostMapping("/auth/loginFailure")
    public String handleLoginFailure(HttpServletRequest request, Model model) {

        Exception exception =
                (Exception) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);

        final String message = getMessage(exception);

        // Server-side logging is a better place for detailed information
        if (exception != null) {
            log.warn("Authentication failed: {}", exception.getMessage());
        }

        model.addAttribute("errorMessage", message);
        return "error/login-failure"; // Thymeleaf template
    }

    private static String getMessage(Exception exception) {
        String message = "Login failed. Please check your username and password.";
        if (exception instanceof LockedException) {
            message = "Your account is locked. Please contact support.";
        } else if (exception instanceof DisabledException) {
            message = "Your account is disabled. Please contact support.";
        } else if (exception instanceof BadCredentialsException) {
            // Keep message generic to avoid leaking details
            message = "Invalid username or password.";
        }
        return message;
    }
}
