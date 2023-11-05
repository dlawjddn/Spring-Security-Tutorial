package io.basic.security.config;

import io.basic.security.exception.auth.AccessDenyHandler;
import io.basic.security.exception.auth.AuthEntryPoint;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.Builder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.io.IOException;
@Builder
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final AuthEntryPoint authEntryPoint;
    private final AccessDenyHandler accessDenyHandler;


    public SecurityConfig(UserDetailsService userDetailsService, AuthEntryPoint authEntryPoint, AccessDenyHandler accessDenyHandler) {
        this.userDetailsService = userDetailsService;
        this.authEntryPoint = authEntryPoint;
        this.accessDenyHandler = accessDenyHandler;
    }
    @Bean
    public static UserDetailsService createUser(){
        /**
         * 메모리의 가상의 사용자들을 생성 -> 빈으로 등록하여 따로 처리 과정이 필요없다
         */
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}dlawjddn")
                .roles("USER")
                .build();

        UserDetails sys = User.builder()
                .username("sys")
                .password("{noop}system")
                .roles("SYS")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("{noop}admin")
                .roles("USER", "SYS", "ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, sys, admin);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        IpAddressMatcher hasIpAddress = new IpAddressMatcher("127.0.0.1");
        http
                //.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/shop/login", "/shop/user").permitAll()
//                        .requestMatchers("/shop/mypage").hasRole("USER")
//                        .requestMatchers("/shop/access/pay").access(((authentication, context) ->
//                                new AuthorizationDecision(hasIpAddress.matches(context.getRequest()))))
//                        .anyRequest().authenticated())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/user/**").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SYS")
                        .anyRequest().authenticated())
                /**
                 *  hasRole() -> 사용자의 권한을 의미함
                 *  hasAuthority() -> 읽기, 쓰기, 수정의 권한을 의미함
                 *  access() -> http 요청의 경로나 ip 주소 등 상세 정보로 인한 인
                 *
                 *  설정 시에 구체적인 경로가 우선적으로 나오고 큰 범위의 경로가 나중에 나오게 해야함
                 */
                .formLogin(form -> form
                        //.loginPage("/login-page") //-> 내가 커스텀한 로그인 페이지로 가는 경우, 지정하지 않으면 spring security에서 기본 제공하는 페이지로 넘어감
                        .defaultSuccessUrl("/")
                        .failureUrl("/login-page")
                        .usernameParameter("userId")
                        .passwordParameter("userPassword")
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                RequestCache requestCache = new HttpSessionRequestCache();
                                HttpServletRequest savedRequest = requestCache.getMatchingRequest(request, response);
                                if (savedRequest == null){
                                    System.out.println("authentication is successed: " + authentication.getName());
                                    response.sendRedirect("/");
                                } else{
                                    String requestURI = savedRequest.getRequestURI();
                                    response.sendRedirect(requestURI);
                                }

                            }
                        })
                        .failureHandler(new AuthenticationFailureHandler() {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                System.out.println("authentication is failed: " + exception.getMessage());
                                response.sendRedirect("/login-page");
                            }
                        })
                        .permitAll())
                        // authorizeHttpRequest.anyRequest().authenticated() 를 통해서 모든 요청에 대해 인증을 요구하지만
                        // Login 로직의 경우 login 에서 인증을 요구하는 건 불가능 -> 로그인 로직에 한해서 모든 요청에 대해 인증 무시 허용
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .addLogoutHandler(new LogoutHandler() {
                            @Override
                            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                                HttpSession session = request.getSession();
                                session.invalidate(); // 세션 무효화
                            }
                        })
                        .logoutSuccessHandler(new LogoutSuccessHandler() {
                            @Override
                            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect("/login");
                            }
                        })
                )//.deleteCookies("remember me"))
                .rememberMe(remember -> remember
                        .tokenValiditySeconds(3600)
                        .rememberMeParameter("remember me")
                        .userDetailsService(userDetailsService))
                .sessionManagement(sManage -> sManage
                                .sessionFixation(sessionFix -> sessionFix
                                        .newSession())
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false))
                        // maxSessionPreventsLogin: true -> 새 인증 요청한 사용자 거부
                        // maxSessionPreventsLogin: false -> 기존 인증 받은 사용자 거부

                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(authEntryPoint)
                        .accessDeniedHandler(accessDenyHandler));



        return http.build();
    }
}
