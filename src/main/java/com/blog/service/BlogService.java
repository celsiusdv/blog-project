package com.blog.service;

import com.blog.entity.Blog;
import com.blog.repository.BlogRepository;
import com.blog.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@Slf4j
@Service
public class BlogService {
    @Autowired
    private BlogRepository blogRepository;
    @Autowired
    private UserRepository userRepository;

    public List<Blog> getBlogs(Integer page){
        if(blogRepository.findAll().isEmpty()) throw new RuntimeException("empty list of blogs");
        else{
            PageRequest pageRequest=PageRequest.of((page-1),4);
            Page<Blog> pages =blogRepository.findAll(pageRequest);
            return pages.getContent();
        }
    }

    public List<Blog> searchBlogs(String wordsToRegex,Integer page){
        List<String> words= Stream.of(wordsToRegex.split(" "))
                .map(String::trim)
                .collect(Collectors.toList());
        log.info("\u001B[35mwords from the client mapped to array: "+words+"\u001B[0m");

        String regex= IntStream.range(0, words.size())
                .filter( i -> i < words.size())
                .mapToObj(i -> "(?=.*[[:<:]]("+words.get(i)+")[[:>:]])")
                .collect(Collectors.joining("|","(?i)^",".*"));

        PageRequest pageRequest=PageRequest.of(page-1,4);
        return blogRepository.searchBlogs(regex,pageRequest)
                .orElseThrow( () ->new RuntimeException("wrong request"));
    }

    public Blog getBlog(Integer id){
        Optional<Blog> blog=blogRepository.findById(id);
        return blog.isPresent() ?
                blog.get()
                : blog.orElseThrow(() -> new RuntimeException("blog not found"));

    }

    @Transactional
    public Blog createBlog(Blog blog, Integer id){
        blog.setUser(userRepository.findById(id).get());
        blogRepository.save(blog);
        System.out.println(blog.getUser());
        return blog;
    }

    public Blog editBlog(Blog blog){
        try{
            Optional<Blog> blogToUpdate= Optional.of(
                    blogRepository.getReferenceById(blog.getBlogId()));//blog from database to be replaced with new values
            log.warn("old blog to be updated: "+blogToUpdate.get());
            blogToUpdate.get().setTitle(blog.getTitle());
            blogToUpdate.get().setPost(blog.getPost());//getUsername returns an email
            log.info("updated: "+blogToUpdate.get());
            return blogRepository.save(blogToUpdate.get());
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }
    }

    public boolean deleteBlog(Integer id){
        try{
            blogRepository.deleteById(id);
            return true;
        }catch (Exception e){
            return false;
        }
    }
}
