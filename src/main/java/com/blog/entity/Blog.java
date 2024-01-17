package com.blog.entity;

import javax.persistence.*;

@Table(name = "blogs")
@Entity(name = "Blog")
public class Blog {
    @Id @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "blog_id")
    private Integer blogId;

    private String title;

    @Column(columnDefinition = "TEXT")
    private String post;

    @ManyToOne
    @JoinColumn(name = "user_id_junction", referencedColumnName = "user_id",
            foreignKey = @ForeignKey(name ="fk_user_blog" ))
    private User user;

    public Blog(){}
    public Blog(String title, String post){
        this.title=title;
        this.post=post;
    }
    public Blog(User user){ this.user=user; }

    public void setTitle(String title){this.title=title;}
    public void setPost(String post){this.post=post;}
    public void setUser(User user){ this.user=user;}

    public Integer getBlogId(){return blogId;}
    public String getTitle(){ return title; }
    public String getPost(){return post;}
    public User getUser(){ return user;}

    @Override
    public String toString() {
        try{
            return "blog {\n"+
                    "\ttitle: "+title+
                    "\tpost: "+post.substring(0,25)+"..."+
                    "\tuser: "+user.getName()+"\n}";
        }catch (StringIndexOutOfBoundsException e){
            return "blog {\n"+
                    "\ttitle: "+title+
                    "\tpost: "+post+
                    "\tuser: "+user.getName()+"\n}";
        }

    }
}
