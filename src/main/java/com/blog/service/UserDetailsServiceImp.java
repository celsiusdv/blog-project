package com.blog.service;

import com.blog.repository.UserRepository;
import com.blog.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImp implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    // 5- fetch user through the @Bean AuthenticationManager from SecurityConfig.class
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user =new User();
        try{
            Optional<User> userToFind=userRepository.findUserByEmail(email);
            if(userToFind.isPresent()) user=userToFind.get();
            return user;//entity that implements UserDetails
        }catch (UsernameNotFoundException e){
            throw new UsernameNotFoundException("invalid user");
        }
    }
}
