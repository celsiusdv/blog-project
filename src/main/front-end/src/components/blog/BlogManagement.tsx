import { Card, CardHeader, Divider, CardBody, CardFooter, Image, Button } from "@nextui-org/react";
import { Dispatch } from "react";
import Restricted from "../../context/Restricted";
import { User } from "../../models/user";

type onClickProps={
    isEditable: boolean;
    setEditable: Dispatch<React.SetStateAction<boolean>>;
    user:User;
    onDelete: () => void;
}
const BlogManagement = ({isEditable, setEditable, user, onDelete}:onClickProps) => {
    return ( 
        <div>
            <Card className="max-w-[400px]" >
                <CardHeader className="flex gap-3">
                    <Image alt="nextui logo" height={40} radius="sm" width={40}
                        src="https://avatars.githubusercontent.com/u/86160567?s=200&v=4" />
                    <div className="flex flex-col">
                        <p className="text-md" style={{ color: "#17bf60" }} >Manage Blog</p>
                        <p className="text-small text-default-500">Name: {user.name}</p>
                        <p className="text-small text-default-500">Role: {user?.authorities![0].authority}</p>
                    </div>
                </CardHeader>
                <Divider />
                <Divider />
                <CardFooter>
                    <Restricted authorities={["ADMIN_delete"]}>
                        <Button className="ml-4" color="danger" variant="flat" onClick={onDelete}>Delete </Button>
                    </Restricted>
                    { !isEditable ?
                        <Button className="ml-5"color="warning" variant="flat" 
                                onClick={()=> setEditable(!isEditable)}>Edit </Button>
                                  :
                        <Button className="ml-5"color="warning" variant="flat" 
                                onClick={()=> setEditable(!isEditable)}>Cancel </Button>}

                    { isEditable &&                                         /* my-form id from BlogView.tsx */
                        <Button className="ml-5"color="success" variant="flat" form="my-form" type="submit">save </Button>}
                </CardFooter>
            </Card>
        </div>
     );
}
 
export default BlogManagement;