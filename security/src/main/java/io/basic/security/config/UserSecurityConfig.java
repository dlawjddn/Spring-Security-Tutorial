package io.basic.security.config;

import io.basic.security.exception.auth.AccessDenyHandler;
import io.basic.security.exception.auth.AuthEntryPoint;
import io.basic.security.handler.LoginFailureHandler;
import io.basic.security.handler.LoginSuccessHandler;
import io.basic.security.handler.LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class UserSecurityConfig {
    private final LoginSuccessHandler loginSuccessHandler;
    private final LoginFailureHandler loginFailureHandler;
    private final LogoutHandler logoutHandler;
    private final UserDetailsService userDetailsService;
    private final AccessDenyHandler accessDenyHandler;
    private final AuthEntryPoint authEntryPoint;

    public UserSecurityConfig(
            LoginSuccessHandler loginSuccessHandler,
            LoginFailureHandler loginFailureHandler,
            LogoutHandler logoutHandler,
            UserDetailsService userDetailsService,
            AccessDenyHandler accessDenyHandler,
            AuthEntryPoint authEntryPoint) {
        this.loginSuccessHandler = loginSuccessHandler;
        this.loginFailureHandler = loginFailureHandler;
        this.logoutHandler = logoutHandler;
        this.userDetailsService = userDetailsService;
        this.accessDenyHandler = accessDenyHandler;
        this.authEntryPoint = authEntryPoint;
    }

    @Bean
    public static UserDetailsService createMemoryUser(){
        UserDetails user = User.builder()
                .username("dlawjddn")
                .password("{noop}dlawjddn")
                .roles("USER")
                .build();

        UserDetails system = User.builder()
                .username("system")
                .password("{noop}system")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}admin")
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, system, admin);
    }
    @Bean
    @Order(2)
    public SecurityFilterChain userFilterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/user/**").hasRole("USER")
                        .anyRequest().authenticated());

        http
                .formLogin(login -> login
                        .defaultSuccessUrl("/")
                        .failureUrl("/login")
                        .successHandler(loginSuccessHandler)
                        .failureHandler(loginFailureHandler)
                        .permitAll());

        http
                .rememberMe(remember -> remember
                        .tokenValiditySeconds(3600)
                        .rememberMeParameter("remember-me")
                        .userDetailsService(userDetailsService));

        http
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler)
                        .deleteCookies("JSESSIONID"));

        http
                .sessionManagement(session -> session
                        .sessionFixation(fix -> fix.newSession())
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false));

        http
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(accessDenyHandler));
                        //.authenticationEntryPoint(authEntryPoint)

        return http.build();
    }
}
