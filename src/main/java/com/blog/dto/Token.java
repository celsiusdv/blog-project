package com.blog.dto;
//used as response for the /refresh-token endpoint
public class Token {
    private String accessToken;
    private String refreshToken;

    public Token(){}
    public Token(String accessToken, String refreshToken){
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
    }
    public void setAccessToken(String accessToken){
        this.accessToken=accessToken;
    }
    public void setRefreshToken(String refreshToken){
        this.refreshToken=refreshToken;
    }

    public String getAccessToken(){
        return this.accessToken;
    }
    public String getRefreshToken(){
        return this.refreshToken;
    }

    @Override
    public String toString() {
        return "Token{" +
                //"accessToken='" + accessToken + '\'' +
                "refreshToken='" + refreshToken + '\'' +
                '}';
    }
}
