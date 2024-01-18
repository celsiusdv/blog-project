import axios from "axios";
import { useAuthContext } from "../context/AuthProvider";
import { UserAuth } from "../models/types";
import { Token } from "../models/login-response";



const useRefreshToken = () => {
    let { auth, setAuth }:UserAuth = useAuthContext();
    let tokens:Token={
        accessToken:auth.accessToken!,
        refreshToken:auth.refreshToken!
    };
    const refresh = async (): Promise<Token> => {
        const response = await axios.post<Token>('/api/authentication/refresh-token',
        tokens,// sends a refresh token to be verified in the server
        {
            headers: { 
                "Accept": "application/json",
                "Content-Type": "application/json" ,
                "Access-Control-Allow-Credentials":true
            },
        });
        tokens=response.data;
        setAuth({//only the access token will be modified
            user:auth.user,
            accessToken:tokens.accessToken,
            refreshToken:tokens.refreshToken
        });
        //console.log("new token: ",tokens);
        return tokens;
    }
    return refresh;
};

export default useRefreshToken;