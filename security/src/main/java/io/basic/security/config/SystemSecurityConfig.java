package io.basic.security.config;

import org.apache.catalina.filters.ExpiresFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SystemSecurityConfig {
    @Bean
    @Order(1)
    public SecurityFilterChain systemFilterChain(HttpSecurity http) throws Exception{
        http
                .securityMatcher("/system")
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/system/**").hasRole("SYS")
                        .anyRequest().authenticated());

        return http.build();
    }
}
