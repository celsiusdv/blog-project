import { useLocation, useNavigate, useParams } from "react-router-dom";
import { userId } from "../../models/types";
import useInterceptor from "../../hooks/useInterceptor";
import { User } from "../../models/user";
import { FormEvent, useEffect, useState } from "react";
import axios from "axios";
import { Button, Input } from "@nextui-org/react";

const ModifyUser = () => {
    const axiosPrivate = useInterceptor();
    const { id } = useParams<userId>();//get the route params '/modify-user/:id' from App.tsx, then the value from AdminPane.tsx
    const location= useLocation();
    const navigate = useNavigate();
    //get the query params from AdminPane.tsx from the action buttons
    const queryAction:string|null = new URLSearchParams(location.search).get('action');
    const queryUser:string|null = new URLSearchParams(location.search).get('user');
    const[name, setName]=useState<string>("");
    const[email,setEmail]=useState<string>("");
    const[password,setPassword]=useState<string>("");
    let user:User={}
    useEffect(() => {
        const getUser = async () => {
            try {
                const response = await axiosPrivate.get<User>(`/api/users/user/${queryUser}`);
                console.log(response.data, " get user by email");
                setName(response.data.name!);
                setEmail(response.data.email!);
            } catch (error) {
                //handle errors & todo: set value in the inputs//
                console.log(error);
            }
        };
        getUser();
    }, []);//this function avoid infinite loop after fething data

    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        user={userId:Number(id),name,email,password}
        console.log(user);
        try {
            if (queryAction === "update") {
                const response = await axiosPrivate.put<User>(`/api/users/user/${id}`,user);
                navigate(-1);
            } else if (queryAction === "delete") {
                const response=await axiosPrivate.delete<User>(`/api/users/user/${id}`);
                navigate(-1);
            }
        } catch (error) {
            if(axios.isAxiosError(error))console.log(error.message);
            console.log(error);
        }
    }
    return ( 
        <div>
            {queryAction} user with id: {id} and email: {queryUser}
            <form onSubmit={(e) => handleSubmit(e)}>
                {queryAction === "update" ?
                    <div>
                        <br />
                        <Input size={"md"} type="text" label="User Name" placeholder="Enter your name" value={name} onChange={(e) => {setName(e.target.value); }} />
                        <br />
                        <Input size={"md"} type="text" label="Email" placeholder="Enter your email" value={email} onChange={(e) => { setEmail(e.target.value); }} />
                        <br />
                        <Input size={"md"} type="text" label="Password" placeholder="Enter your new password" value={password} onChange={(e) => { setPassword(e.target.value); }} />
                        <br />
                        <Button type="submit">{queryAction}</Button>
                    </div> :
                    <div>
                        <Input size={"md"} type="text" label="User Name" disabled value={name} onChange={(e) => {setName(e.target.value); }} />
                        <Button type="submit">{queryAction}</Button>
                    </div>}
            </form>
        </div>
    );
}
 
export default ModifyUser;