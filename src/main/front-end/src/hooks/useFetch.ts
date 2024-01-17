import { useState, useEffect } from "react";
import useInterceptor from "./useInterceptor";
import axios from "axios";

export const useFetch = (url: string) => {
    const axiosPrivate = useInterceptor();
    const [data, setData] = useState<any[]>([]);
    const [isLoading, setIsLoading] = useState<boolean>(true);
    const [error, setError] = useState<DOMException | unknown | null>(null);
    
    useEffect(() => {
        let isMounted = true;
        const abortFetch:AbortController = new AbortController();
        const signal: AbortSignal = abortFetch.signal
        const getData = async () => {
            try {              //wait untill this variable it's completely filled to pass
                const response = await axiosPrivate.get(url, {signal});
                if(isMounted){
                    setData(response.data);//fill setData() once the response await is completed
                    setIsLoading(false);//once the data is completely filled, set the template loading to false
                    setError(null);//if the data is completely filled, set the error template to null
                }
            } catch (error: unknown) {
                if (axios.isAxiosError(error)) {
                    axios.isCancel(error) && console.log("fetch:" + error.message + ", unmount component");
                } else {
                    //if the data is not found or there is another kind of error, set the template loading to false and replace it with error
                    setIsLoading(false);
                    setError(error);
                }
            }
        }
        getData();
        return () => {
            isMounted = false;
            abortFetch.abort();//abort the fetching to unmount the component after switching between components in the page
        }
    }, [url]);

	return { data, isLoading, error };//return from the useFetch
};