package com.blog.repository;

import com.blog.entity.Blog;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface BlogRepository extends JpaRepository<Blog, Integer> {

    /*    @Query(value = """ mariadb syntax
                SELECT * FROM blogs WHERE title REGEXP (:regex)
                                        OR post REGEXP (:regex)
                """, nativeQuery = true)*/
    @Query(value = """
            SELECT * FROM blogs WHERE title ~ (:regex)
                                    OR post ~ (:regex)
            """, nativeQuery = true)
    Optional<List<Blog>> searchBlogs(@Param("regex") String regex, Pageable pages);

}
