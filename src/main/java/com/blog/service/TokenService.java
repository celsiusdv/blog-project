package com.blog.service;

import com.blog.exceptions.TokenException;
import com.blog.repository.RefreshTokenRepository;
import com.blog.repository.UserRepository;
import com.blog.entity.RefreshToken;
import com.blog.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
@Slf4j
@Service
public class TokenService {
    @Autowired private JwtEncoder jwtEncoder;
    @Autowired private UserRepository userRepository;
    @Autowired private RefreshTokenRepository refreshTokenRepository;

    //6- generate an access token for the logged user if it is successfully authenticated
    public String createJwtAccessToken(User user){
        Instant now = Instant.now();
        Instant thirtyMinutes=ZonedDateTime.now().plusMinutes(30).toInstant();
        //Instant thirtyMinutes=ZonedDateTime.now().plusMinutes(1).toInstant();
        String role = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .subject(user.getName())
                .expiresAt(thirtyMinutes)
                .claim("roles", role)
                .build();
        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }


    public RefreshToken createUUIDRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken(
                UUID.randomUUID().toString(),
                ZonedDateTime.now().plusMinutes(1440).toInstant(),//24hs
                //ZonedDateTime.now().plusMinutes(3).toInstant(),
                user);
        return refreshTokenRepository.save(refreshToken);//- saving the refresh token to a database
    }

    public Optional<RefreshToken> findRefreshToken(String refreshToken) {
        return refreshTokenRepository.findRefreshToken(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        try{
            if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
                log.warn("checking token expiration...\ntoken expired, deleting token: "
                        +token.getRefreshToken()+ " with id: "+token.getRefreshTokenId());
                refreshTokenRepository.deleteToken(token.getRefreshToken());
                refreshTokenRepository.flush();
                throw new TokenException("Refresh token: "+token.getRefreshToken()+" was expired. Please make a new signin request");
            } else {
                log.info("\u001B[35m"+"checking token expiration...\nrefresh token still valid! :D"+"\u001B[0m");
                return token;
            }
        }catch (Exception e){
            throw new TokenException(e.getMessage());//get the exception message from the above block
        }
    }
}
