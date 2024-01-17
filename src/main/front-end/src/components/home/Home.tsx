import { Input, Pagination, Tooltip } from "@nextui-org/react";
import { useFetch } from "../../hooks/useFetch";
import { FetchedBlogs } from "../../models/types";
import BlogList from "../blog/BlogList";
import { SearchIcon } from "../icons/SearchIcon";
import "./home.css";
import { useRef, useState } from "react";


const Home = () => {
    let currentPage = 1;
    const [url,setUrl]=useState(`/api/blogs/page/${currentPage}`);
    const {data:blogs}:FetchedBlogs=useFetch(url);
    const browse=useRef<string>("");
    const search =() =>{
        //if the input is not empty switch the endoint to search new values
        browse.current !== "" 
        ? setUrl(`/api/blogs/search/${currentPage}/${browse.current}`)
        : setUrl(`/api/blogs/page/${1}`);//go to the first page if the event in the input gets an empty string
    };
    
    const loadBlogs = () => {
        //if the input is empty, fetch blogs without using the search endpoint
        (browse.current === "")
            ? setUrl(`/api/blogs/page/${currentPage}`)
            : search();
    }
    return ( 
        <div className="home" tabIndex={0}>
            <Tooltip showArrow={true} content="click in the search icon or press enter to search">
                <Input className="w-full sm:max-w-[44%] m-7 search-input" isClearable placeholder="Search blogs"
                    startContent={<SearchIcon className={"search-icon"}
                                            onClick={() => search()} />}
                                            onChange={(e) => browse.current = e.target.value}
                                            onKeyDown={(e) => e.key === "Enter" && search()} />
            </Tooltip>
            <Pagination isCompact color="secondary" showControls
                total={10} initialPage={currentPage} onChange={(page) => {
                    currentPage=page;
                    loadBlogs();
                }} />
            <BlogList blogs={blogs} />
        </div>
     );
}
 
export default Home;