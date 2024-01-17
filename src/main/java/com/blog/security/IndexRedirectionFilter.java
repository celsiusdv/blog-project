package com.blog.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/*filter that redirect all request to the index.html after every refresh, so the
* SPA page can render items without setting a blank page*/
@Slf4j
@Component
public class IndexRedirectionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setHeader("Access-Control-Allow-Methods", "*");
        response.setHeader("Access-Control-Allow-Methods", "POST, GET, PUT, OPTIONS, DELETE");
        response.setHeader("Access-Control-Allow-Headers", "*");
        response.setHeader("Access-Control-Allow-Headers","Origin, X-Requested-With, Content-Type, Accept, X-Auth-Token, X-Csrf-Token, Authorization");
        response.setHeader("Access-Control-Allow-Credentials", "false");
        response.setHeader("Access-Control-Max-Age", "3600");

        String path = request.getRequestURI().toLowerCase();
        //log.info("first filtering for path: " + path);
        if (!path.equals("/") &&
                !path.startsWith("/api") &&
                !path.startsWith("/static") &&
                !path.startsWith("/manifest.json") &&
                !path.startsWith("/favicon.ico") &&
                !path.startsWith("/robots.txt") &&
                !path.endsWith("xml") &&
                !path.endsWith("json") &&
                !path.endsWith("jpg") &&
                !path.endsWith("jpeg") &&
                !path.endsWith("gif") &&
                !path.endsWith("png")) {
            //log.warn("redirection to /index.html from path: " + path);
            request.getRequestDispatcher("/index.html").forward(request, response);
            return;
        }
        //log.info("IndexRedirectionFilter sent along its way path: " + path);
        filterChain.doFilter(request, response);
    }
}


