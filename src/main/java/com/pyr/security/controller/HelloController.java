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


    /**
     * 当前登录的用户，有ADMIN或者MANAGER的角色
     */
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    @RequestMapping("/roleAuth2")
    public String role2() {
        return "admin Auth  222!";
    }

    /**
     * 传过来的id小于10 且 传过来的userName和数据库查出来的username相等
     */
    @PreAuthorize("#id< 10 and principal.username.equals(#username)")
    @RequestMapping("/roleAuth3")
    public String role3(Integer id, String username) {
        return "admin Auth  33!";
    }
}
