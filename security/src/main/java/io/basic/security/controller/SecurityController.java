package io.basic.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {
    @GetMapping("/")
    public String defaultHome(){
        return "home";
    }
    @GetMapping("/login-page")
    public String loginPage(){
        return "login-page";
    }
    @GetMapping("/user")
    public String user(){
        return "user-page";
    }
    @GetMapping("/admin/pay")
    public String onlyAdmin(){
        return "only admin";
    }
    @GetMapping("/admin")
    public String exceptUser(){
        return "except user";
    }
}
