package com.pyr.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {
    @RequestMapping("/")
    public String index() {
        return "index!";
    }

    @RequestMapping("/hello")
    public String hello() {
        return "hello springboot!";
    }


    // RoleVoter 里定义了角色名，使用的时候，都必须使用ROLE_作为前缀
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping("/roleAuth")
    public String role() {
        return "admin Auth!";
    }
}
