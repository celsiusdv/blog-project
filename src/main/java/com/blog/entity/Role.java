package com.blog.entity;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Table(name = "roles")
@Entity(name="Role")
public class Role implements GrantedAuthority {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    private Integer roleId;

    private String authority;

    //using only {CascadeType.MERGE, CascadeType.REFRESH} to avoid duplicate entries
    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.MERGE, CascadeType.REFRESH})
    @JoinTable(name = "roles_and_privileges",
            joinColumns = @JoinColumn(name = "role_id_junction", referencedColumnName = "role_id",
                    foreignKey = @ForeignKey(name = "fk_role_id_and_privileges")),
            inverseJoinColumns = @JoinColumn(name = "privilege_id_junction", referencedColumnName = "privilege_id",
                    foreignKey = @ForeignKey(name = "fk_privilege_id")))
    private Set<Privilege> privileges=new HashSet<>();

    public Role(){}
    public Role(String authority){ this.authority=authority;}

    public void setRoleId(Integer roleId){ this.roleId=roleId; }
    public void setAuthority(String authority){ this.authority=authority; }
    public void setPrivileges(Set<Privilege> privileges){ this.privileges=privileges; }

    public Integer getRoleId(){ return this.roleId;}
    @Override public String getAuthority() {
        return authority;
    }
    public Set<Privilege> getPrivileges(){ return privileges; }

    @Override
    public String toString() {
        return "{" +
                "\n\t\troleId: "+roleId+"\n\t\tauthority: "+this.authority+" {\n"+
                "\t\t\tprivileges: "+this.privileges+"\n}";
    }
}
