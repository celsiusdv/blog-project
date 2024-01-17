package com.blog.controller;

import com.blog.entity.Blog;
import com.blog.service.BlogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(path = "/api/blogs")
@CrossOrigin("https://demojavablog.onrender.com")
public class BlogController {

    @Autowired private BlogService blogService;

    @GetMapping(path = "/page/{page}")
    public ResponseEntity<List<Blog>> getBlogs(@PathVariable("page")Integer page){
        return new ResponseEntity<>(blogService.getBlogs(page),HttpStatus.OK);
    }

    @GetMapping(path = "/search/{page}/{search}")
    public ResponseEntity<List<Blog>>searchBlogs(@PathVariable("page")Integer page,
                                                 @PathVariable("search") String search){
        return new ResponseEntity<>(blogService.searchBlogs(search,page),HttpStatus.OK);
    }

    @GetMapping(path = "/blog/{id}")
    public ResponseEntity<Blog>getBlog(@PathVariable("id") Integer id){
        return new ResponseEntity<>(blogService.getBlog(id),HttpStatus.OK);
    }

    @PreAuthorize("hasAnyRole('ADMIN_create','USER_create')")
    @PostMapping(path ="/blog")
    public ResponseEntity<Blog> createBlog(@RequestBody Blog blog){
        System.out.println(blog);
        return new ResponseEntity<>(blogService.createBlog(blog, blog.getUser().getUserId()),HttpStatus.CREATED);
    }

    @PreAuthorize("hasAnyRole('ADMIN_edit','USER_edit')")
    @PutMapping(path = "/blog")
    public ResponseEntity<Blog> updateBlog(@RequestBody Blog blog){
        return new ResponseEntity<>(blogService.editBlog(blog),HttpStatus.OK);
    }

    @PreAuthorize("hasAnyRole('ADMIN_delete')")
    @DeleteMapping(path = "/blog/{id}")
    public ResponseEntity<Boolean> deleteBlog(@PathVariable("id") Integer id){
        return blogService.deleteBlog(id) ? new ResponseEntity<>(HttpStatus.OK) :
                new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
