import { Button, Input } from "@nextui-org/react";
import { ChangeEvent, FormEvent, useEffect, useState } from "react";
import { User } from "../../models/user";
import axios from "axios";
import { useNavigate } from "react-router-dom";

const Register = () => {
    const navigate = useNavigate();
    ///validators
    const [name,setName]=useState<string>("");
    const [requiredUserName,setRequiredUserName]=useState<boolean>(true);
    const handleRequiredUserName=(event:ChangeEvent<HTMLInputElement>)=>{
        if(event.target.value.length > 0){
            setRequiredUserName(false);
            setName(event.target.value);
        }else setRequiredUserName(true);
    }

    const [email,setEmail]=useState<string>("");
    const [requiredEmail,setRequiredEmail]=useState<boolean>(true);
    const handleRequiredEmail=(event:ChangeEvent<HTMLInputElement>)=>{
        if(event.target.value.length > 0){
            setRequiredEmail(false);
            setEmail(event.target.value);
        }else setRequiredEmail(true);
    }

    const [password,setPassword]=useState<string>("");
    const [requiredPassword,setRequiredPassword]=useState<boolean>(true);
    const handleRequiredPassword=(event:ChangeEvent<HTMLInputElement>)=>{
        if(event.target.value.length > 0){
            setRequiredPassword(false);
            setPassword(event.target.value);
        }else setRequiredPassword(true);
    }

    const [match,setMatch]=useState<string>("");
    const [requiredMatch,setRequiredMatch]=useState<boolean>(true);
    const handleRequiredMatch=(event:ChangeEvent<HTMLInputElement>)=>{
        if(event.target.value.length > 0){
            setRequiredMatch(false);
            setMatch(event.target.value);
        }else setRequiredMatch(true);
    }
    useEffect( () =>{
        if(password !== match){
            setRequiredPassword(true);
            setRequiredMatch(true);
            console.log("password doesn't match");
        } else {
            setRequiredPassword(false);
            setRequiredMatch(false);
        }
    },[password,match]);//check the password whenever these two dependencies get a new value

    //submit user object
    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const user: User = { name, email, password };
        console.log("saving... ", user);

        try {        //wait until the fetching is complete          
            const response = await axios.post<User>("http://localhost:8080/api/authentication/register",
            user,//object to send to the server
                {
                    headers: { 
                        "Accept": "application/json",
                        "Content-Type": "application/json" ,
                        "Access-Control-Allow-Credentials":true
                    },
                }
            );
            console.log("request to the server-> ",user,"\nresponse from the server->",response.data);
            navigate("/");
        } catch (error:unknown) {
            if(axios.isAxiosError(error)){
                if(error.response?.status === 500){
                    console.log("error in client side while trying to register with credentials: "
                    ,user,"\n",error.response.data);//error.response.data.message
                }
            }
        }
    }
    return (
        <div className="w-full flex flex-col gap-4 place-items-center p-8">{/* main panel */}
            <h1>Register User</h1>
            <form key={"sm"} className="flex w-4/12 flex-col md:flex-nowrap mb-6 md:mb-0 gap-4"
                onSubmit={(e) =>handleSubmit(e)}>

                <Input size={"md"} type="text" label="User Name" placeholder="Enter your name"
                    isRequired={requiredUserName} onChange={(event) =>handleRequiredUserName(event)}/>

                <Input size={"md"} type="email" label="Email" placeholder="Enter your email"
                    isRequired={requiredEmail} onChange={(event) =>handleRequiredEmail(event)}/>

                <Input size={"md"} type="text" label="Password" placeholder="Enter your password"
                    isRequired={requiredPassword} onChange={(event) =>handleRequiredPassword(event)}/>

                <Input size={"md"} type="text" label="Confirm Password" placeholder="Confirm your password"
                    isRequired={requiredMatch} onChange={(event) => handleRequiredMatch(event)} />

                <Button color="secondary" variant="flat" type="submit">
                    Sign Up
                </Button>
            </form>

        </div>
    );
};

export default Register;