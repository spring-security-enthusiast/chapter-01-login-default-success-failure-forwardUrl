package com.example.demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.security.Principal;


@Controller
public class LoginController {

    @GetMapping(value = {"/auth/login"})
    public String login(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/home"; // or whatever your post-login page is
        }
        return "auth/login"; // Renders the Thymeleaf template (e.g., auth/login.html)
    }

    @PostMapping("/customSuccessPage")
    public String customSuccessPage(Model model, Principal principal) {
        return "custom";
    }
}
