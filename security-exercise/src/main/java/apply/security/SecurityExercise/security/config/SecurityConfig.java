package apply.security.SecurityExercise.security.config;

import apply.security.SecurityExercise.security.handler.CustomAccessDeniedHandler;
import apply.security.SecurityExercise.security.handler.CustomAuthenticationFailureHandler;
import apply.security.SecurityExercise.security.handler.CustomAuthenticationSuccessHandler;
import apply.security.SecurityExercise.security.provider.CustomAuthenticationProvider;
import apply.security.SecurityExercise.security.service.CustomUserDetailsService;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final CustomUserDetailsService customUserDetailsService;
    private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler authenticationFailureHandler;
    private final CustomAccessDeniedHandler accessDeniedHandler;
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
//    @Bean
//    @Builder
//    public UserDetailsService createUser(){
//        String password = passwordEncoder().encode("dlawjddn");
//
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER")
//                .build();
//
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER")
//                .build();
//
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN")
//                .build();
//        return new InMemoryUserDetailsManager(user, manager, admin);
//    }
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web
                .ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }
    @Bean
    public AuthenticationManager authenticationManager(
            CustomUserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        CustomAuthenticationProvider authenticationProvider = new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
        return new ProviderManager(authenticationProvider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(request -> request
                        .requestMatchers("/", "/users", "/users/login/**", "/login*").permitAll()
                        .requestMatchers("/mypage").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/messages").hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers("/config").hasAnyRole("ADMIN")
                        .anyRequest().authenticated());

        http
                .formLogin(login -> login
                        .loginPage("/login")
                        .loginProcessingUrl("/login_proc")
                        .defaultSuccessUrl("/")
                        .successHandler(authenticationSuccessHandler)
                        .failureUrl("/login")
                        .failureHandler(authenticationFailureHandler)
                        .permitAll());

        http
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(accessDeniedHandler));

        return http.build();
    }
}
