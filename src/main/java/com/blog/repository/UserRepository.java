package com.blog.repository;

import com.blog.entity.User;
import com.sun.istack.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.lang.NonNullApi;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User,Integer> {

    //auto-generate a custom search SQL query
    Optional<User> findUserByEmail(String email);//custom Query

    @Override
    @Modifying
    @Transactional
    void delete(User entity);
}
