import { LoginResponse } from "./login-response";
import { Role } from "./user";

type FetchedData = {//typechecking for users using useFetch in AdminPane.tsx
    data: User[];
    isLoading: Boolean;
    error: string | unknown;
};
type FetchedBlogs = {//typechecking for blogs from useFetch Home.tsx
    data: Blog[];
    isLoading: Boolean;
    error: string | unknown;
};
//typechecking specifically for the table in AdminPane.tsx because the NextUI table component can't hold
//directly the array of roles
type UserTable={
    userId:number;
    name:string;
    email:string;
    role:string;
}

//------types for Authentication///////////////////////
type UserAuth = {//typechecking to set props value in AuthContext.Provider
    auth: LoginResponse;
    setAuth: React.Dispatch<React.SetStateAction<LoginResponse>>;
};

//-----props ///////////////////
type AuthContextProps = {//props to set in AuthProvider.tsx
    children: React.ReactNode;
};
type RoleProps={// props to set in RequireAuth.tsx
    authorities:string[];
}
type RestrictedProps={//props to set in Restricted.tsx
    authorities:string[];
    children: React.ReactNode;
}
type BlogProps={//props to set in BlogList.tsx
    blogs:Blogs[];
}

//////////////////////////////////////////////
type column = {//typechecking for columns in AdminPane component
    name: string,
    uid: string;
};
type userId = {// typechecking for useParams in ModifyUser component
    id: string;
};
