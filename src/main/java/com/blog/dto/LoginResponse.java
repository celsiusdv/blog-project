package com.blog.dto;

import com.blog.entity.User;

public record LoginResponse(User user, String accessToken, String refreshToken) {
}
