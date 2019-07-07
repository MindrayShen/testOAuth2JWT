package com.test.testoauth2jwt.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;


public class TokenFilter implements Filter {


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
       HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
       //token verify login
        httpServletRequest.setAttribute("username","slw");
        httpServletRequest.setAttribute("mobile","123456894651");



    }
}
