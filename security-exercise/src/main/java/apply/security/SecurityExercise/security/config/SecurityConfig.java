package apply.security.SecurityExercise.security.config;

import apply.security.SecurityExercise.security.service.CustomUserDetailsService;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    @Bean
    @Builder
    public UserDetailsService createUser(){
        String password = passwordEncoder().encode("dlawjddn");

        UserDetails user = User.builder()
                .username("user")
                .password(password)
                .roles("USER")
                .build();

        UserDetails manager = User.builder()
                .username("manager")
                .password(password)
                .roles("MANAGER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password(password)
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, manager, admin);
    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web
                .ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService);
        return auth.build();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/", "/users").permitAll()
                        .requestMatchers("/mypage").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/messages").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/config").hasAnyRole("ADMIN")
                        .anyRequest().authenticated());

        http
                .formLogin();

        return http.build();
    }
}
