package com.test.testoauth2jwt.filter;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.test.testoauth2jwt.controller.UserController;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

@Component
public class TokenFilter implements Filter {

    private  String[] url={"/user/login"};

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
       HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
       //token verify login
        String requestURI = httpServletRequest.getRequestURI();
        boolean contains = Arrays.asList(url).contains(requestURI);
        if(contains){
            filterChain.doFilter(servletRequest,servletResponse);//继续执行路径controller方法
            return;
        }

        String token = httpServletRequest.getHeader("token");

        byte[] decode = Base64.getDecoder().decode(token);
        Algorithm algorithm = Algorithm.HMAC256("slwsec");
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("slwsrv")
                .build(); //Reusable verifier instance
        String string = new String(decode);//byte[]转换成string    如果直接tostring()得到的是栈地址
        DecodedJWT jwt = verifier.verify(string);

        httpServletRequest.setAttribute("username",jwt.getSubject());
        filterChain.doFilter(servletRequest,servletResponse);

    }
}
