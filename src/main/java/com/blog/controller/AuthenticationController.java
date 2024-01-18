package com.blog.controller;

import com.blog.dto.Token;
import com.blog.dto.LoginResponse;
import com.blog.entity.User;
import com.blog.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/authentication")
@CrossOrigin("https://blog-project-production-8107.up.railway.app/")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;


    @PostMapping(path = "/register")
    public ResponseEntity<User> createUser(@RequestBody User user){
        return new ResponseEntity<>(authenticationService
                .registerUser(user.getName(),user.getEmail(),user.getPassword()), HttpStatus.CREATED);
    }

    @PostMapping("/login") // 1- The client send a request to this endpoint, before the request is completed,it will go to a series of filters, check SecurityConfig.class,
    public ResponseEntity<LoginResponse> loginUser(@RequestBody User user) {
        return new ResponseEntity<>(authenticationService
                .login(user.getUsername(), user.getPassword()),HttpStatus.OK);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<Token>refreshToken(@RequestBody Token token){
        return new ResponseEntity<>( authenticationService.refreshToken(token.getRefreshToken()),HttpStatus.OK );
    }

}
