import { User } from "./user";

export type Blog={
    blogId?:number;
    title?:string;
    post?:string;
    user?:User;
}