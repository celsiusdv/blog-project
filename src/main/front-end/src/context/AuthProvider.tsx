import { createContext, useContext, useState } from "react";
import { UserAuth, AuthContextProps } from "../models/types";
import { LoginResponse } from "../models/login-response";

//this wraps all the information we need to send to its children components
//the AuthContext value is filled in Login.tsx component
const AuthContext = createContext<UserAuth| undefined>(undefined);

export const AuthProvider = ({ children }: AuthContextProps) => {
    const [auth, setAuth] = useState<LoginResponse>({});
    if(AuthContext === undefined)throw new Error("no value found for AuthContext.Provider");
    return (
        <AuthContext.Provider value={{ auth, setAuth }}>{/* load user with the credentials */}
            {children}
        </AuthContext.Provider>
    )
}
export default AuthContext;

export const useAuthContext = () =>{//get the credentials once is filled through the useState in AuthProvider
    const loginResponse =useContext<UserAuth|undefined>(AuthContext);
    if(loginResponse === undefined){
        throw new Error("useAuthContext is undefined");
    }
    return loginResponse;
}



