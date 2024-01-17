package com.blog;

import com.blog.repository.BlogRepository;
import com.blog.repository.RefreshTokenRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Main {

	public static void main(String[] args) {
		SpringApplication.run(Main.class, args);
	}

/*	@Bean
	public CommandLineRunner commandLineRunner(BlogRepository repository, RefreshTokenRepository tokenRepository){
		return args -> {
			//System.out.println(blogService.createBlog(new Blog("this is a blog test"),1));
			//System.out.println(blogService.searchBlogs("asdf debian hello security"));
			//PageRequest pageRequest=PageRequest.of(0,4);
			//Page<Blog> pages =repository.findAll(pageRequest);
			//System.out.println(pages.getContent());
			//tokenRepository.deleteAllTokens(4);
		};
	}*/
}
