import { requireChatGPTUser } from "./chatgpt-auth";
import Scheduler from "./scheduler";
export const dynamic = "force-dynamic";
export default async function Home() { await requireChatGPTUser("/"); return <Scheduler/>; }
