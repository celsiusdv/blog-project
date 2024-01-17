import React from "react";
import { LoginResponse } from "../models/login-response";
import { RestrictedProps, UserAuth } from "../models/types";
import { Role } from "../models/user";
import { useAuthContext } from "./AuthProvider";

const Restricted = ({authorities, children}:RestrictedProps) => {
    const { auth }: UserAuth = useAuthContext();
    const { user }: LoginResponse = auth;
    let isAuthority:boolean=false;
    //check if authority exist and whether the case is true, render the children
    const renderChild =():JSX.Element | undefined =>{
        user?.authorities?.forEach((role: Role) => {
            if(isAuthority)return;//break the iteration if the authority is found
            for(let i=0; i<authorities.length; i++){
                if(role.authority === authorities[i]){
                    isAuthority=true;
                    break;
                }
            }
        }
        );
        if(isAuthority) return <div>{children}</div>
    }
    return (    
        <React.Fragment>
            {renderChild()}
        </React.Fragment>
     );
}
 
export default Restricted;