import { User } from "./user";

export type LoginResponse={
    user?:User;
    accessToken?:string;
    refreshToken?:string;
    isLoggedIn?:boolean;
}
export type Token={
    accessToken:string;
    refreshToken:string;
}