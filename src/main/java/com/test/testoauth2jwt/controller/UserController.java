package com.test.testoauth2jwt.controller;


import com.alibaba.fastjson.JSON;
import com.test.testoauth2jwt.dto.UserLoginDto;
import com.test.testoauth2jwt.po.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/login")
    public String login(UserLoginDto userLoginDto) throws Exception {
        String username = userLoginDto.getUsername();
        String password = userLoginDto.getPassword();
        if(username != null && !username.equals("slw")){
            throw new Exception("user doesn't exist");
        }
        if(password != null && !password.equals("123456")){
            throw new Exception("password in incorrect");
        }

        User user = new User();
        user.setUsername("slw");
        user.setMobile("12345678952");
        user.setEmail("aa@qq.com");
        user.setRole("admin");

        String s = JSON.toJSONString(user);
        return s;
    }

}

