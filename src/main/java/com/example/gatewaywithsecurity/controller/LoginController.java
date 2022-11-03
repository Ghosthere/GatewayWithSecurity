package com.example.gatewaywithsecurity.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/user/login")
    public void login() {
        System.out.println("login");
    }
}
