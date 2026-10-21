import { env } from "cloudflare:workers";
import { getChatGPTUser } from "@/app/chatgpt-auth";
export const dynamic = "force-dynamic";
async function bridge(request:Request, method:string) {
  if (!(await getChatGPTUser())) return Response.json({error:"Sign in required"},{status:401});
  if(method==="POST" && (request.headers.get("origin")!==new URL(request.url).origin || request.headers.get("content-type")?.split(";")[0]!=="application/json"))
    return Response.json({error:"Invalid request"},{status:403});
  const settings=env as unknown as {SENDER_URL?:string;SENDER_TOKEN?:string;SENDER_PAUSED_REASON?:string};
  if(settings.SENDER_PAUSED_REASON) return Response.json({error:settings.SENDER_PAUSED_REASON},{status:503});
  if(!settings.SENDER_URL || !settings.SENDER_TOKEN) return Response.json({error:"The sender is being connected. Please check back shortly."},{status:503});
  const endpoint=new URL(settings.SENDER_URL);
  if(endpoint.protocol!=="https:" || !endpoint.hostname.endsWith(".lambda-url.ap-southeast-1.on.aws")) return Response.json({error:"Sender configuration needs attention"},{status:503});
  try {
    const body=method==="POST"?await request.text():undefined;
    if(body && new TextEncoder().encode(body).length>80000)return Response.json({error:"Message too large"},{status:413});
    const result=await fetch(endpoint.toString(),{method,headers:{Authorization:"Bearer "+settings.SENDER_TOKEN,"Content-Type":"application/json"},body,signal:AbortSignal.timeout(28000),redirect:"manual"});
    if(result.status>=300 && result.status<400) throw new Error("Sender returned an unexpected redirect");
    return new Response(await result.text(),{status:result.status,headers:{"Content-Type":"application/json","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
  } catch (error) { console.error("Sender connection:", error instanceof Error ? error.message.replaceAll(settings.SENDER_TOKEN,"[redacted]").slice(0,240) : "unavailable"); return Response.json({error:"Could not confirm the result. Refresh the list before trying again."},{status:503}); }
}
export async function GET(request:Request){return bridge(request,"GET")}
export async function POST(request:Request){return bridge(request,"POST")}
