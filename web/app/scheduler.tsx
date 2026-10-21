"use client";
import {useEffect,useRef,useState} from "react";
import {ArrowUpRight, Check, CheckCheck, Clock3, LoaderCircle, MessageCircle, Paperclip, Plus, RefreshCw, Send, ShieldCheck, X} from "lucide-react";
type Chat={id:string;name:string};
type Job={id:string;chat_name:string;text:string;attachment?:{name:string;size:number};due_at:number;created_at:number;status:string;error?:string;result_info?:{error?:string}};
type DraftFile={id:string;file:File;uploaded:boolean};
type Reply={error?:string;scheduled?:boolean;upload?:{url:string;fields:Record<string,string>}};
function fileSize(n:number){return n<1024?`${n} B`:n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(1)} MB`;}
type Data={connected:boolean;chats:Chat[];jobs:Job[];connection_error?:string;refreshed_at?:number};
const empty:Data={connected:false,chats:[],jobs:[]};
const pending=["queued","scheduled","sending"];
function parts(date:Date,zone:string){return Object.fromEntries(new Intl.DateTimeFormat("en-CA",{timeZone:zone,year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).formatToParts(date).map(p=>[p.type,p.value]));}
function localValue(date:Date,zone:string){const p=parts(date,zone);return p.year+"-"+p.month+"-"+p.day+"T"+p.hour+":"+p.minute;}
function toUTC(value:string,zone:string) {
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value))throw new Error("Choose a date and time.");
  const target=Date.parse(value+"Z");let result=target;
  for(let i=0;i<4;i++){const shown=Date.parse(localValue(new Date(result),zone)+"Z");result+=target-shown;}
  if(localValue(new Date(result),zone)!==value)throw new Error("This time does not exist because the clocks change. Choose another time.");
  return new Date(result);
}
function display(seconds:number,zone:string){return new Intl.DateTimeFormat("en",{timeZone:zone,month:"short",day:"numeric",hour:"numeric",minute:"2-digit",timeZoneName:"short"}).format(seconds*1000)}
const labels:Record<string,string>={queued:"Confirming schedule",scheduled:"Scheduled",sending:"Sending",sent:"Sent",cancelled:"Cancelled",failed:"Not sent",unknown:"Check LINE",expired:"Missed send time"};
export default function Scheduler(){
 const [data,setData]=useState<Data>(empty),[loaded,setLoaded]=useState(false),[error,setError]=useState(""),[notice,setNotice]=useState("");
 const [chat,setChat]=useState(""),[search,setSearch]=useState(""),[text,setText]=useState(""),[when,setWhen]=useState(""),[zone,setZone]=useState("UTC");
 const [busy,setBusy]=useState(false),[refreshing,setRefreshing]=useState(false),[tab,setTab]=useState("upcoming");
 const [files,setFiles]=useState<DraftFile[]>([]),[dragging,setDragging]=useState(false),[progress,setProgress]=useState("");
 const filePicker=useRef<HTMLInputElement>(null),submitting=useRef(false);
 const requestId=useRef(""),formRef=useRef<HTMLTextAreaElement>(null);
 async function load(){try{const r=await fetch("/api/scheduler",{cache:"no-store"});const d=await r.json() as Data & {error?:string};if(!r.ok)throw new Error(d.error);setData(d);setLoaded(true);}catch(e){setLoaded(true);setData(previous=>({...previous,connected:false}));setError(e instanceof Error?e.message:"Could not load messages.");}}
 useEffect(()=>{const z=Intl.DateTimeFormat().resolvedOptions().timeZone;setZone(z);setWhen(localValue(new Date(Date.now()+3600000),z));load();const timer=setInterval(load,15000);return()=>clearInterval(timer);},[]);
 useEffect(()=>{requestId.current="";},[text]);
 useEffect(()=>{const prevent=(e:DragEvent)=>{if(e.dataTransfer?.types.includes("Files"))e.preventDefault()};window.addEventListener("dragover",prevent);window.addEventListener("drop",prevent);return()=>{window.removeEventListener("dragover",prevent);window.removeEventListener("drop",prevent)}},[]);
 function addFiles(selected:FileList|null){
  if(!selected||busy)return;
  const incoming=Array.from(selected);setError("");
  if(files.length+incoming.length>5){setError("Attach up to 5 files at a time.");return;}
  if(incoming.some(f=>f.size>20*1024*1024)){setError("Each file must be 20 MB or smaller.");return;}
  if(incoming.some(f=>!f.name||new TextEncoder().encode(f.name).length>255||/[\\/\u0000-\u001f\u007f-\u009f]/.test(f.name))){setError("Use filenames without slashes or control characters, up to 255 bytes.");return;}
  setFiles(current=>[...current,...incoming.map(file=>({id:crypto.randomUUID().replaceAll("-",""),file,uploaded:false}))]);
 }
 async function post(body:unknown){const r=await fetch("/api/scheduler",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});const d=await r.json() as Reply;if(!r.ok)throw new Error(d.error);return d;}
 async function upload(item:DraftFile){
  if(item.uploaded)return;
  const hash=Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",await item.file.arrayBuffer())),b=>b.toString(16).padStart(2,"0")).join("");
  const prepared=await post({action:"upload",id:item.id,name:item.file.name,size:item.file.size,sha256:hash});
  if(!prepared.scheduled){
   if(!prepared.upload)throw new Error("Could not prepare the upload.");
   const target=new URL(prepared.upload.url);
   if(target.protocol!=="https:"||!/^.+\.s3[.-]ap-southeast-1\.amazonaws\.com$/.test(target.hostname))throw new Error("Invalid upload destination.");
   const form=new FormData();for(const [key,value] of Object.entries(prepared.upload.fields))form.append(key,value);form.append("file",item.file);
   const result=await fetch(target,{method:"POST",body:form,credentials:"omit",redirect:"error",signal:AbortSignal.timeout(120000)});
   if(!result.ok)throw new Error("Upload failed. Nothing was scheduled for this file.");
  }
  item.uploaded=true;setFiles(current=>current.map(f=>f.id===item.id?{...item}:f));
 }
 async function submit(immediate=false){
  if(submitting.current)return;setError("");setNotice("");let accepted=0;
  try{
   if(!chat)throw new Error("Choose a conversation.");
   if(!text.trim()&&!files.length)throw new Error("Write a message or attach a file.");
   const due=immediate?new Date():toUTC(when,zone);
   if(!immediate && due.getTime()<Date.now()+60000)throw new Error("Choose a send time at least one minute from now.");
   submitting.current=true;setBusy(true);
   // Upload first so a failed upload cannot leave only the text scheduled.
   for(const item of files){setProgress(`Uploading ${item.file.name}…`);await upload(item);}
   setProgress("Scheduling…");
   const common={action:"schedule",chat,due_at:due.toISOString(),timezone:zone,immediate};
   if(text.trim()){
    requestId.current ||= crypto.randomUUID().replaceAll("-","");
    await post({...common,id:requestId.current,text});accepted++;setText("");requestId.current="";
   }
   for(const item of files){await post({...common,id:item.id,text:"",file:true});accepted++;setFiles(current=>current.filter(f=>f.id!==item.id));}
   setNotice(immediate?`${accepted} message${accepted===1?"":"s"} queued for sending.`:`${accepted} message${accepted===1?"":"s"} scheduled.`);
   await load();
  }catch(e){setError((accepted?`${accepted} message${accepted===1?"":"s"} already accepted. `:"")+(e instanceof Error?e.message:"Could not confirm scheduling. Refresh before trying again."));await load();}finally{submitting.current=false;setBusy(false);setProgress("");}
 }
 async function refresh(){
  setRefreshing(true);setError("");try{await post({action:"refresh"});setNotice("Refreshing conversations…");setTimeout(()=>{load();setRefreshing(false)},8000);}
  catch(e){setError(e instanceof Error?e.message:"Could not refresh.");setRefreshing(false);}
 }
 async function cancel(id:string){setError("");try{await post({action:"cancel",id});await load();setNotice("Scheduled message cancelled.");}catch(e){setError(e instanceof Error?e.message:"Could not cancel.");}}
 const upcoming=data.jobs.filter(j=>pending.includes(j.status));
 const shown=(tab==="upcoming"?upcoming:data.jobs.filter(j=>!pending.includes(j.status))).sort((a,b)=>tab==="upcoming"?a.due_at-b.due_at:b.created_at-a.created_at);
 const filtered=data.chats.filter(c=>c.name.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
 const zones=Array.from(new Set([zone,"Asia/Bangkok","America/Los_Angeles","Asia/Singapore","Europe/London","UTC"]));
 let preview="Choose when it should arrive";try{if(when)preview=display(toUTC(when,zone).getTime()/1000,zone);}catch{}
 return <div className="workspace">
  <aside className="sidebar">
   <a href="/" className="brand"><span className="brand-mark"><MessageCircle size={22}/><Clock3 size={12}/></span><span>LINE<span className="brand-sub">Scheduler</span></span></a>
   <button className="compose-link" onClick={()=>formRef.current?.focus()}><Plus size={18}/> New message</button>
   <nav aria-label="Messages"><button className={tab==="upcoming"?"active":""} onClick={()=>setTab("upcoming")}><Clock3 size={18}/> Scheduled <span>{upcoming.length}</span></button><button className={tab==="history"?"active":""} onClick={()=>setTab("history")}><CheckCheck size={18}/> History</button></nav>
   <div className="connection"><span className={"status-dot "+(data.connected?"online":"")}/><strong>{data.connected?"LINE connected":loaded?"Sending paused":"Connecting…"}</strong></div>
   <div className="sidebar-foot"><ShieldCheck size={15}/><span>Private to you</span></div>
  </aside>
  <main>
   <h1 className="sr-only">LINE Scheduler</h1>
   {error&&<div className="feedback error" role="alert">{error}<button aria-label="Dismiss error" onClick={()=>setError("")}><X size={16}/></button></div>}
   {notice&&<div className="feedback success" role="status"><Check size={16}/>{notice}<button aria-label="Dismiss notification" onClick={()=>setNotice("")}><X size={16}/></button></div>}
   <div className="main-grid">
    <section className={"composer "+(dragging?"dragging":"")} aria-labelledby="composer-title" onDragOver={e=>{if(e.dataTransfer.types.includes("Files")){e.preventDefault();setDragging(true)}}} onDragLeave={e=>{if(!e.currentTarget.contains(e.relatedTarget as Node))setDragging(false)}} onDrop={e=>{e.preventDefault();setDragging(false);addFiles(e.dataTransfer.files)}}>
     <fieldset className="compose-fields" disabled={busy}>
     <div className="section-heading"><h2 id="composer-title">New message</h2></div>
     <div className="recipient-row"><label htmlFor="recipient">To</label><select id="recipient" value={chat} onChange={e=>setChat(e.target.value)}><option value="">Choose a conversation</option>{filtered.map(c=><option value={c.id} key={c.id}>{c.name}</option>)}</select><button className={"icon-button "+(refreshing?"spinning":"")} onClick={refresh} disabled={refreshing} title="Refresh conversations" aria-label="Refresh conversations"><RefreshCw size={17}/></button></div>
     {data.chats.length>15&&<input className="chat-search" aria-label="Filter conversations" placeholder="Find a conversation…" value={search} onChange={e=>setSearch(e.target.value)}/>}
     <label className="sr-only" htmlFor="message">Message</label><textarea id="message" ref={formRef} value={text} onChange={e=>setText(e.target.value)} maxLength={10000} placeholder="Message"/>
     <div className="message-meta"><span><ShieldCheck size={14}/> Letter Sealing required</span><span>{text.length.toLocaleString()} / 10,000</span></div>
     <div className="attachments">
      <input ref={filePicker} type="file" multiple className="sr-only" tabIndex={-1} aria-label="Choose attachments" onChange={e=>{addFiles(e.target.files);e.target.value=""}}/>
      <button type="button" className="attach-button" onClick={()=>filePicker.current?.click()}><Paperclip size={16}/>{dragging?"Drop files here":"Attach files"}</button><span className="attachment-hint">or drop here · 20 MB each</span>
      {files.length>0&&<><ul className="file-list">{files.map(item=><li key={item.id}><Paperclip size={14}/><span>{item.file.name}<small>{fileSize(item.file.size)}</small></span><button aria-label={`Remove ${item.file.name}`} onClick={()=>setFiles(current=>current.filter(f=>f.id!==item.id))}><X size={15}/></button></li>)}</ul><p className="file-note">Each attachment sends separately. Images send as files.</p></>}
      {progress&&<p className="file-note" role="status">{progress}</p>}
     </div>
     <div className="delivery">
      <h3><Clock3 size={17}/> Send time</h3>
      <div className="time-fields"><label>Date & time<input aria-label="Send date and time" type="datetime-local" value={when} onChange={e=>setWhen(e.target.value)}/></label><label>Time zone<select aria-label="Time zone" value={zone} onChange={e=>{const instant=(()=>{try{return toUTC(when,zone)}catch{return new Date(Date.now()+3600000)}})();setZone(e.target.value);setWhen(localValue(instant,e.target.value));}}>{zones.map(z=><option key={z}>{z}</option>)}</select></label></div>
      <div className="presets"><button onClick={()=>setWhen(localValue(new Date(Date.now()+3600000),zone))}>In one hour</button><button onClick={()=>{const p=parts(new Date(Date.now()+86400000),zone);setWhen(p.year+"-"+p.month+"-"+p.day+"T09:00");}}>Tomorrow, 9 am</button></div>
     </div>
     <div className="composer-footer"><p>{preview}<small>Usually within a minute of the selected time.</small></p><button className="schedule-button" disabled={busy||!data.connected||!chat||(!text.trim()&&!files.length)} onClick={()=>submit()}>{busy?<LoaderCircle className="spinning" size={17}/>:<Send size={17}/>}Schedule send</button></div>
     <div className="send-now-row"><button disabled={busy||!data.connected||!chat||(!text.trim()&&!files.length)} onClick={()=>submit(true)}>Send now <ArrowUpRight size={14}/></button></div>
     </fieldset>
    </section>
    <section className="outbox" aria-labelledby="outbox-title">
     <div className="section-heading"><h2 id="outbox-title">Messages</h2><button className="icon-button" aria-label="Refresh message status" onClick={()=>{setError("");load()}}><RefreshCw size={16}/></button></div>
     <div className="tabs"><button className={tab==="upcoming"?"selected":""} onClick={()=>setTab("upcoming")}>Scheduled <span>{upcoming.length}</span></button><button className={tab==="history"?"selected":""} onClick={()=>setTab("history")}>History</button></div>
     {!loaded?<div className="empty"><LoaderCircle className="spinning" size={30}/><h3>Loading messages…</h3></div>:shown.length===0&&error?<div className="empty"><Clock3 size={30}/><h3>Messages unavailable</h3></div>:shown.length===0?<div className="empty"><h3>{tab==="upcoming"?"No scheduled messages":"No message history"}</h3></div>:<div className="job-list">{shown.map(job=><article className="job" key={job.id}><div className="job-heading"><span className="avatar">{Array.from(job.chat_name)[0]||"?"}</span><div><h3>{job.chat_name}</h3><time dateTime={new Date(job.due_at*1000).toISOString()}>{display(job.due_at,zone)}</time></div><span className={"badge "+job.status}>{labels[job.status]||job.status}</span></div><p className="job-text">{job.text}</p>{job.attachment&&<p className="job-file"><Paperclip size={14}/>{job.attachment.name}<small>{fileSize(job.attachment.size)}</small></p>}{(job.error||job.result_info?.error)&&<p className="job-error">{job.error||job.result_info?.error}</p>}{["queued","scheduled"].includes(job.status)&&<button className="cancel" onClick={()=>cancel(job.id)}>Cancel send</button>}</article>)}</div>}
     <p className="outbox-note">Times shown in {zone.replaceAll("_"," ")}.<br/>History is kept for 90 days.</p>
    </section>
   </div>
  </main>
 </div>
}
