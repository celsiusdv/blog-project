package com.blog.repository;

import com.blog.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Integer> {
    @Query("SELECT new RefreshToken(t.refreshTokenId, t.refreshToken, t.expiryDate, t.user)" +
            " FROM  RefreshToken t WHERE t.refreshToken=:token")
    Optional<RefreshToken> findRefreshToken(@Param("token") String token);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.refreshToken = :token")
    void deleteToken(@Param("token")String token);

}
