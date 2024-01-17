import { useNavigate, useParams } from "react-router-dom";
import { Blog } from "../../models/blog";
import useInterceptor from "../../hooks/useInterceptor";
import { FormEvent, useEffect, useRef, useState } from "react";
import axios from "axios";
import { Divider } from "@nextui-org/react";
import BlogManagement from "./BlogManagement";
import { useAuthContext } from "../../context/AuthProvider";
import { UserAuth } from "../../models/types";
import Restricted from "../../context/Restricted";

const BlogView = () => {
    const axiosPrivate = useInterceptor();
    const navigate = useNavigate();
    const { auth }: UserAuth = useAuthContext();
    const { blogId } = useParams();//get route params <Route path='/blog-view/:blogId' from App.tsx
    const [edit, setEdit]= useState<boolean>(false);
    const [blog, setBlog] = useState<Blog>();//render the blog object in the DOM
    const title=useRef<HTMLTextAreaElement>(null);//use ref to set values in the blog object and send to the server
    const post=useRef<HTMLTextAreaElement>(null);

    //fetch blog
    useEffect(() => {
        const abortFetch: AbortController = new AbortController();
        const signal: AbortSignal = abortFetch.signal;
        const getBlog = async () => {
            try {
                const response = await axiosPrivate.get<Blog>(`/api/blogs/blog/${blogId}`,{ signal });
                setBlog(response.data);
            } catch (error) {
                if (axios.isAxiosError(error)) {
                    axios.isCancel(error) && console.log("fetch:" + error.message + ", unmount BlogView component");
                }
            }
        };
        getBlog();
        return () => abortFetch.abort();
    }, []);
    //update blog
    const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        const blogRef: Blog = {
            blogId: parseInt(blogId!),
            title: title.current?.value,
            post: post.current?.value,
            user: auth.user
        };
        try {
            const response = await axiosPrivate.put<Blog>('/api/blogs/blog/', blogRef);
            setBlog(response.data);
            setEdit(!edit);//disable the save button after updating the blog
        } catch (error) {
            if (axios.isAxiosError(error)) console.log(error.message);
            console.log(error);
        }
    }
    const handleDelete = async() =>{
        try {
            const response = await axiosPrivate.delete<Blog>(`/api/blogs/blog/${blogId}`);
            navigate(-1);
            console.log(response.status);
        } catch (error) {
            if (axios.isAxiosError(error)) console.log(error.message);
            console.log(error);
        }
    }
    return ( 
        <div className="blog-container">
            
            {!edit &&
             <article className="blog">
                <h1>{blog?.title}</h1>
                <Divider />
                <p>{blog?.post}</p>
            </article>}

            {edit===true &&
             <form className="blog" onSubmit={(e) =>handleSubmit(e)} id="my-form">
                <textarea className="edit-title" defaultValue={blog?.title} ref={title} />
                <Divider />
                <textarea className="edit-post" defaultValue={blog?.post} ref={post} />
                {/* the submit button is in BlogManagement child component with id as form="my-form" */}
            </form>}
            
            <div className="management-pane">
                <Restricted authorities={["ADMIN_edit", "USER_edit"]}>
                    <BlogManagement isEditable={edit} setEditable={setEdit} user={auth.user!} onDelete={handleDelete} />
                </Restricted>
            </div>
            

        </div>
     );
}
 
export default BlogView;