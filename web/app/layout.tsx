import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {title:"LINE Scheduler",description:"Schedule messages from your LINE account.",icons:{icon:"/favicon.svg"}};
export default function Layout({children}:Readonly<{children:React.ReactNode}>){return <html lang="en"><body>{children}</body></html>;}
