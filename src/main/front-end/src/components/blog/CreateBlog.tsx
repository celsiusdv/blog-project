import { Button, Input, Textarea } from "@nextui-org/react";
import { FormEvent, useState } from "react";
import { Blog } from "../../models/blog";
import { useAuthContext } from "../../context/AuthProvider";
import { UserAuth } from "../../models/types";
import useInterceptor from "../../hooks/useInterceptor";
import { useNavigate } from "react-router-dom";

const CreateBlog = () => {
    const { auth }: UserAuth = useAuthContext();
    const axiosPrivate = useInterceptor();
    const [title,setTitle]=useState<string>("");
    const [post,setPost]=useState<string>("");
    const navigate = useNavigate();
    let blog:Blog={}
    const handleSubmit = async (event: FormEvent<HTMLFormElement>) =>{
        event.preventDefault();
        blog={
            title:title,
            post:post,
            user:auth.user
        };
        await axiosPrivate.post<Blog>("/api/blogs/blog/",blog);
        navigate("/");
    }
    return ( 
        <div className="create-blog">
            <div className="left-pane"></div>
            <form className="inputs" onSubmit={(e) => handleSubmit(e)}>
                <h1>Create Blog</h1>
                    <Input label="Title" variant="bordered" placeholder="Enter Title"
                        classNames={{ base: "max-w-2xl min-h-24 pb-4" }} size="lg"
                        onChange={e => setTitle(e.target.value)}
                        />
                    <Textarea label="Post" variant="bordered" placeholder="Enter your Post"
                        classNames={{ base: "max-w-2xl", input: "resize-y h-3/4" }} size="lg"
                        onChange={e => setPost(e.target.value)}
                        />
                    <Button className="mt-3" color="primary" variant="flat" type="submit">Create </Button>
            </form>
        </div>
     );
}
 
export default CreateBlog;