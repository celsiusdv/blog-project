package com.blog.entity;

import javax.persistence.*;

@Table(name = "privileges")
@Entity(name="Privilege")
public class Privilege {
    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "privilege_id")
    private Integer privilegeId;

    private String privilege;

    public Privilege(){}
    public Privilege(String privilege){this.privilege=privilege;}
    //overloading constructor to fetch specific column data in jpql query in PermissionRepository
    public Privilege(Integer privilegeId, String privilege){
        this.privilegeId=privilegeId;
        this.privilege=privilege;
    }

    public void setPrivilegeId(Integer privilegeId) {this.privilegeId = privilegeId;}
    public void setPrivilege(String privilege){ this.privilege=privilege; }

    public Integer getPrivilegeId() { return privilegeId; }
    public String getPrivilege(){ return this.privilege; }

    @Override
    public String toString() {
        return "\n\t\t\t\t{\n" +
                "\t\t\t\t\tprivilegeId: "+privilegeId+"\n"+
                "\t\t\t\t\tprivilege: "+privilege;
    }
}
