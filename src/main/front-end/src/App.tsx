import { BrowserRouter, Route, Routes } from 'react-router-dom';
import Navbar from './components/navbar/NavigationBar';
import Register from './components/navbar/Register';
import Home from './components/home/Home';
import AdminPane from './components/admin/AdminPane';
import ModifyUser from './components/admin/ModifyUser';
import Login from './components/navbar/Login';
import RequireAuth from './context/RequireAuth';
import BlogView from './components/blog/BlogView';
import CreateBlog from './components/blog/CreateBlog';

function App() {

	return (
		<BrowserRouter>
			<Navbar />
			<Routes>{/* only one route and component shows at time */}
				<Route path='/' index element={<Home />} />{/* path to the Home component */}
				<Route path='/signup' element={<Register />} />
				<Route path='/login' element={<Login />} />
				<Route element={<RequireAuth authorities={["ADMIN_read","USER_read"]}/>}>
					<Route path='/admin-pane' element={<AdminPane />} />{/*SET ADMIN PANE VISIBLE FOR AUTHENTICATED USERS */}
				</Route>
				<Route element={<RequireAuth authorities={["ADMIN"]} />}>
					<Route path='/modify-user/:id' element={<ModifyUser />} />{/*:id is the parameter used in AdminPane to delete or edit user*/}
				</Route>
				<Route element={<RequireAuth authorities={["ADMIN_create","USER_create"]}/>}>
					<Route path='/create-blog' element={<CreateBlog />} />
				</Route>
				<Route path='/blog/:blogId' element={<BlogView />} />{/*id filled in BlogList.tsx*/}
			</Routes>

		</BrowserRouter>

	);
}

export default App;
