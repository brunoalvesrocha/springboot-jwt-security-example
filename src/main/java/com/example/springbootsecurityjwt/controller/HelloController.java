package com.example.springbootsecurityjwt.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @RequestMapping(value = "/api/hello")
    public String sayHello() {
        return "Hello authentication with JWT";
    }
}
