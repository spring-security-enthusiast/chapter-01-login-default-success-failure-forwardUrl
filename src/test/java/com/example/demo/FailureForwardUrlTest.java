package com.example.demo;

import com.example.demo.config.UserConfig;
import com.example.demo.controller.LoginController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.web.servlet.PathRequest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(LoginController.class)
@AutoConfigureMockMvc
@Import({
        FailureForwardUrlTest.TestSecurityConfig.class,
        UserConfig.class
})
public class FailureForwardUrlTest {

    @Autowired
    private MockMvc mvc;

    @Test
    @DisplayName("Should forward to custom failureForwardUrl")
    void testFailureForward() throws Exception {
        // Perform failed login
        mvc.perform(post("/auth/login_processing")
                        .param("username", "invalid_user")
                        .param("password", "wrong_password")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(forwardedUrl("/auth/loginFailure"));
    }


    @Test
    @DisplayName("POST to loginFailure should render content")
    void testFailurePageContentViaPost() throws Exception {
        // Create a mock authentication exception
        Exception authException = new BadCredentialsException("Bad credentials");

        // Perform POST directly to failure endpoint
        mvc.perform(post("/auth/loginFailure")
                        .requestAttr(WebAttributes.AUTHENTICATION_EXCEPTION, authException)
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Invalid username or password.")))
                .andDo(print());

    }

    @TestConfiguration
    @EnableWebSecurity
    static class TestSecurityConfig {

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
            http
                .csrf(Customizer.withDefaults()) // CSRF protection configuration
                .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers(
                            PathRequest.toStaticResources().atCommonLocations(),
                            PathPatternRequestMatcher.withDefaults().matcher("/auth/**"),
                            PathPatternRequestMatcher.withDefaults().matcher("/error/**")
                    ).permitAll()
                    .anyRequest().authenticated()
                )
                .formLogin(formLogin -> formLogin
                    .loginPage("/auth/login")          // GET: show the login page
                    .loginProcessingUrl("/auth/login_processing") // POST: process the login form
                    .successForwardUrl("/customSuccessPage") // @PostMapping - Specify the home page
                    .failureForwardUrl("/auth/loginFailure") // Specify the URL for server-side forward upon authentication failure
                    .permitAll()                       // also whitelists /auth/login (GET + POST)
                );
            return http.build();
        }
    }
}