import { useLocation, Outlet, Navigate } from "react-router-dom";
import { useAuthContext } from "./AuthProvider";
import { Role} from "../models/user";
import React from "react";
import { RoleProps, UserAuth } from "../models/types";
import { LoginResponse } from "../models/login-response";
import { text } from "stream/consumers";


const RequireAuth = ({ authorities }: RoleProps) => {
    const { auth }: UserAuth = useAuthContext();
    const { user }: LoginResponse = auth;
    const location = useLocation();
    let isRole: boolean = false;
    const authorizeRender = () => {
        try {
            user?.authorities!.forEach((role: Role) => {
                if (isRole === true) return;
                for (let j = 0; j < authorities.length; j++) {
                    //compare the array of roles from the authenticated user against the RoleProps
                    if (role.authority === authorities[j]) {
                        //console.log("role detected: " + role.authority);
                        isRole = true;
                    }
                }
                //console.log("is ", role.authority, " in props? ", isRole);
            });
            if(user === undefined || user === null) throw new Error("authentication not found, redirecting to login");
        } catch (error) {
            /*
            * if any non aunthenticated user reach the endpoint, the user.authorities will be empty
            * therefore an error will be thrown for a redirection to the login page
            */
            return <Navigate to="/login" state={{ from: location }} replace />;
        }
        if (isRole === true) return <Outlet />;//render the child component inside <RequireAuth> in App nested routes
        else return (user !== null) && <div style={{
                                            fontSize:70,
                                            textAlign:"center"
                                        }}> unauthorized </div>;//return this component if the user exist but without the required role
    };

    return (
        <React.Fragment>
            {authorizeRender()}
        </React.Fragment>
    );
};
export default RequireAuth;