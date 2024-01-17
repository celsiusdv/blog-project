import { Image } from "@nextui-org/react";
import { Link } from "react-router-dom";
import { Blog } from "../../models/blog";
import { BlogProps } from "../../models/types";
import './blog.css';

const BlogList = ({blogs}:BlogProps) => {
    return ( 
        <div className="container">
            <h1>List of Blogs</h1>
            {blogs.map((blog: Blog, i) => (
                
                <article className="blog-list" key={i}>
                    <Link to={`/blog/${blog.blogId}`}>{/* this link send us to the BlogView.tsx */}
                        <div className="header">
                            <div className="image">
                                <Image alt="nextui logo" height={40} radius="sm" width={40}
                                    src="https://avatars.githubusercontent.com/u/86160567?s=200&v=4"
                                />
                            </div>
                            <div className="title">
                                <h2 style={{ color: "#17bf60" }}>{blog.title}</h2>
                                <p>written by: {blog.user?.name}</p>
                            </div>
                        </div>
                        <div className="blog-preview">
                            <p>{blog.post?.substring(0, 200) + "..."}</p>
                        </div>
                    </Link>
                </article>
            )
            )}
        </div>
    );
}
 
export default BlogList;

