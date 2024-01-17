package com.blog.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name="email_constraint", columnNames = {"email"} )
})
@Entity(name = "User")
public class User implements UserDetails{
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "user_id")
    private Integer userId;

    @Column
    private String name;

    @NotBlank @Column(nullable = false)
    private String email;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @NotBlank @Column(nullable = false)
    private String password;

    //configuring CascadeType to delete row from table users_and_roles first, to avoid conflict with "users" table
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE, CascadeType.PERSIST, CascadeType.REFRESH})
    @JoinTable(name = "users_and_roles",
            joinColumns = @JoinColumn(name = "user_id_junction", referencedColumnName = "user_id",
                    foreignKey = @ForeignKey(name = "fk_user_id")),
            inverseJoinColumns = @JoinColumn(name = "role_id_junction", referencedColumnName = "role_id",
                    foreignKey = @ForeignKey(name = "fk_role_id")))
    private Set<Role> authorities;

    @OneToOne(mappedBy = "user",
            cascade = {CascadeType.ALL},orphanRemoval = true)
    private RefreshToken refreshToken;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "user",
            cascade = {CascadeType.PERSIST, CascadeType.REMOVE}, orphanRemoval = true)
    private List<Blog> blogs=new ArrayList<>();


    public User(){}
    public User(String email, String password, Set<Role> authorities){
        this.email=email;
        this.password=password;
        this.authorities=authorities;
    }
    public User(String name, String email, String password, Set<Role> authorities){
        this.name=name;
        this.email=email;
        this.password=password;
        this.authorities=authorities;
    }


    public void setName(String name){
        this.name=name;
    }
    public void setEmail(String email){
        this.email=email;
    }
    public void setPassword(String password){
        this.password=password;
    }
    public void setAuthorities(Set<Role> authorities){
        this.authorities=authorities;
    }
    //set blogs method...
    public void removeBlog(Blog blog) {
        blogs.remove(blog);
        blog.setUser(null); // Remove the association from the Blog entity
    }


    public Integer getUserId(){ return this.userId; }
    public String getName(){ return this.name; }
    public String getEmail() {return this.email;}
    @JsonIgnore //hide password on request. use @JsonProperty in the instance field variable declaration
    public String getPassword(){ return this.password; }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //list of mapped users from database to set in SimpleGrantedAuthority
        List<GrantedAuthority> roles = new ArrayList<>();
        for (Role role: this.authorities) {//merge the parent list of authorities with the child list of privileges
            roles.add(new SimpleGrantedAuthority(role.getAuthority()));
            for(Privilege privilege:role.getPrivileges()){
                roles.add(new SimpleGrantedAuthority(role.getAuthority()+"_"+privilege.getPrivilege()));
            }
        }
        return roles;
    }

    @JsonIgnore public List<Blog> getBlogs(){ return blogs; }
    @Override public String getUsername(){ return this.getEmail(); }
    @Override @JsonIgnore public boolean isAccountNonExpired() {return true;}
    @Override @JsonIgnore public boolean isAccountNonLocked() {return true;}
    @Override @JsonIgnore public boolean isCredentialsNonExpired() {return true;}
    @Override @JsonIgnore public boolean isEnabled() {return true;}


    @Override
    public String toString() {
        return //"user id: "+userId+
                    "\n"+"name: "+name+
                    "\nemail: "+email+
                    //"\npassword: "+password+
                    "\nauthorities: "+authorities;
    }
}
