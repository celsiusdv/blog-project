import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import { NextUIProvider } from "@nextui-org/react";
import {ThemeProvider as NextThemesProvider} from "next-themes";
import { AuthProvider } from './context/AuthProvider';


const root = ReactDOM.createRoot(
    document.getElementById('root') as HTMLElement
);
root.render(
    <React.StrictMode>
        <NextUIProvider>
            <NextThemesProvider attribute="class" defaultTheme="dark">
                <AuthProvider>
                                                      {/*dark gray bg*/}
                    <main className="dark text-foreground bg-content1 min-h-screen">
                        <App />
                    </main>
                </AuthProvider>
            </NextThemesProvider>
        </NextUIProvider>
    </React.StrictMode>
);
