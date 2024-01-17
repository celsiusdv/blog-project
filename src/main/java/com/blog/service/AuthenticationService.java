package com.blog.service;

import com.blog.dto.Token;
import com.blog.exceptions.RepeatedEmailException;
import com.blog.exceptions.TokenException;
import com.blog.exceptions.UserNotFoundException;
import com.blog.repository.PrivilegeRepository;
import com.blog.repository.RoleRepository;
import com.blog.repository.UserRepository;
import com.blog.dto.LoginResponse;
import com.blog.entity.Privilege;
import com.blog.entity.RefreshToken;
import com.blog.entity.Role;
import com.blog.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
@Slf4j
@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private PrivilegeRepository privilegeRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private TokenService tokenService;

    //3- authenticate the user
    public LoginResponse login(String username, String password){
        User user=null;
        Token token =new Token();
        RefreshToken refreshToken;
        try {
            Authentication auth =//Authenticate the user for the ProviderManager in SecurityConfig.class, @Bean AuthenticationManager
                    authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            if(auth.isAuthenticated()){
                user= (User) auth.getPrincipal();
                token.setAccessToken(tokenService.createJwtAccessToken(user));
                refreshToken=tokenService.createUUIDRefreshToken(user);
                token.setRefreshToken(refreshToken.getRefreshToken());
                log.info("authenticated user: "+ user);
            }
            return new LoginResponse(user, token.getAccessToken(), token.getRefreshToken());
        }catch (AuthenticationException e) { throw new UserNotFoundException("invalid user"); }
    }

    //get roles and privileges and set to the user before persisting in the method registerUser()
    private Set<Role> userRole(String roleName){
        Optional<Role> role = roleRepository.findByRoleName(roleName);//get role from database
        Set<Role> roles = new HashSet<>();     //to get admin or user permissions switch getUserPermissions() to getAdminPermissions()
        Set<Privilege> privileges = new HashSet<>(privilegeRepository.getUserPermissions());// get all privileges from database
        if(role.isPresent()){
            role.get().setPrivileges(privileges);//add child list of privileges to the role
            roles.add(role.get());//add the role with child list of privileges to set in the User entity
        }
        return roles;
    }

    public User registerUser(String name, String email, String password) {
        Optional<User> existingUser = userRepository.findUserByEmail(email);
        if (existingUser.isPresent()) {
            log.error("email is already in use :(");
            throw new RepeatedEmailException("This email is already in use :(");
        }
        else {                                                        //to add an admin just replace "USER" by "ADMIN"
            User recordUser = new User(name, email, passwordEncoder.encode(password), userRole("USER"));
            return userRepository.save(recordUser);
        }
    }

    public Token refreshToken(String refreshTokenRequest){
        RefreshToken refreshToken;
        User user;
        String accessToken="";
        try{
            Optional<RefreshToken> checkToken=tokenService.findRefreshToken(refreshTokenRequest);
            if(checkToken.isPresent() && refreshTokenRequest != null){
                refreshToken= checkToken.get();
                log.info("\u001B[35muser with token id:"+refreshToken.getRefreshTokenId()+" is requesting a refresh"+"\u001B[0m");
                //returns a token (which contains a user), or an exception if it has expired
                user=tokenService.verifyExpiration(refreshToken).getUser();
                accessToken = tokenService.createJwtAccessToken(user);
                log.info("\u001B[35mgenerated new access token: "+accessToken+"\u001B[0m");
            } else throw new TokenException("invalid token or user is null");
        }catch(Exception e){
            log.warn(e.getMessage());
            throw new TokenException(e.getMessage());
        }
        return new Token(accessToken, refreshToken.getRefreshToken());
    }
}