import { FormEvent, useContext, useState } from "react";
import "./navbar.css";
import axios from "axios";
import { User } from "../../models/user";
import AuthContext from "../../context/AuthProvider";
import { UserAuth } from "../../models/types";
import { LoginResponse } from "../../models/login-response";
import { Button, Input } from "@nextui-org/react";
import { useNavigate } from "react-router-dom";

const Login = () => {
    const navigate = useNavigate();
    const authContext  = useContext<UserAuth | undefined>(AuthContext);//fill the data and manage it in AuthProvider.tsx
    const [email,setEmail]=useState<string>("john@doe.com");
    const [password,setPassword]=useState<string>("hello");//default admin input just for testing purposes

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) =>{
        event.preventDefault();
        let body: User = { email, password };
        let loginResponse:LoginResponse={};
        try {        //wait until the fetching is complete          
            const response = await axios.post<LoginResponse>("http://localhost:8080/api/authentication/login",
            body,//object to send to the server
                {
                    headers: { 
                        "Accept": "application/json",
                        "Content-Type": "application/json" ,
                        "Access-Control-Allow-Credentials":true
                    },
                }
            );
            loginResponse=response.data;
            loginResponse.isLoggedIn=true;
            authContext?.setAuth(loginResponse);
            //console.log("request to the server-> ",body,"\nresponse from the server->",loginResponse);
            navigate("/");
        } catch (error:unknown) {
            if(axios.isAxiosError(error)){
                if(error.response?.status === 500){
                    console.log("error in client side while trying to log in with credentials: "
                    ,body,"\n",error.response.data);//error.response.data.message
                }
            }
        }
    }
    return (//w-full flex flex-col gap-4 place-items-center p-8
        <div className="w-full flex flex-col gap-4 place-items-center p-8">
            <h1>Log In</h1>
            <form key={"sm"} className="flex w-4/12 flex-col md:flex-nowrap mb-6 md:mb-0 gap-4"
                onSubmit={(e) =>handleSubmit(e)}>
                <Input size={"md"} type="text" label="Email" placeholder="Enter your email"
                     onChange={(event) =>setEmail(event.target.value)} value={email} />
                <Input size={"md"} type="text" label="Password" placeholder="Enter your password"
                    onChange={(event) =>setPassword(event.target.value)} value={password} />
                <Button color="primary" variant="flat" type="submit">
                    Log in
                </Button>
            </form>
        </div>
    );
};

export default Login;