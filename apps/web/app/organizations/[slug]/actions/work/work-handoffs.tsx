"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
type State="REQUESTED"|"ACCEPTED"|"DECLINED"|"CANCELLED";
type Handoff={
 id:string;workItemId:string;requesterUserId:string|null;recipientUserId:string;
 status:State;label:string;reason:string;response:string|null;revision:number;
 requestedAt:string;decidedAt:string|null;expiresAt:string|null;
 mayDecide:boolean;mayCancel:boolean;
 requester:{name:string;email:string}|null;
 recipient:{name:string;email:string};
 workItem:{title:string;status:string;assigneeUserId:string|null;
  finding:{title:string;severity:string;status:string}};
};
type Result={total:number;limited:boolean;rows:Handoff[];
 summary:{total:number;awaiting:number;expired:number;accepted:number;declined:number;cancelled:number};
 disclaimer:string};
type Candidate={id:string;title:string;status:string};
type Assignee={role:string;user:{id:string;name:string;email:string}};
async function json<T>(url:string,options?:RequestInit):Promise<T>{
 const response=await fetch(url,{...options,cache:"no-store"});
 const body:unknown=await response.json();
 if(!response.ok){
  if(body&&typeof body==="object"&&"error" in body)
   throw new Error(String((body as {error:unknown}).error));
  throw new Error(`HTTP ${response.status}`);
 }
 return body as T;
}
function date(value:string|null){
 if(!value)return "No deadline";
 const parsed=new Date(value);
 return Number.isNaN(parsed.getTime())?"Unknown":parsed.toISOString().slice(0,16).replace("T"," ");
}
export default function WorkHandoffs({slug,canManage,userId}:{
 slug:string;canManage:boolean;userId:string
}){
 const root=`/api/organizations/${encodeURIComponent(slug)}/actions/work`;
 const url=`${root}/handoffs`;
 const [model,setModel]=useState<Result|null>(null);
 const [people,setPeople]=useState<Assignee[]>([]);
 const [work,setWork]=useState<Candidate[]>([]);
 const [view,setView]=useState<"ALL"|"INBOX"|"PENDING">("INBOX");
 const [loading,setLoading]=useState(true);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [showRequest,setShowRequest]=useState(false);
 const [workId,setWorkId]=useState("");
 const [recipient,setRecipient]=useState("");
 const [reason,setReason]=useState("");
 const [expires,setExpires]=useState("");
 const [reply,setReply]=useState<Record<string,string>>({});
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const result=await json<Result>(`${url}?view=${view}`);
   setModel(result);setError("");
  }catch(e){setError(e instanceof Error?e.message:"Cannot load handoffs.");}
  finally{setLoading(false);}
 },[url,view]);
 useEffect(()=>{void load();},[load]);
 useEffect(()=>{
  if(!canManage)return;
  void Promise.all([
   json<{assignees:Assignee[]}>(`${root}?meta=assignees`),
   json<{rows:Candidate[]}>(`${root}?pageSize=100`)
  ]).then(([members,tasks])=>{
   setPeople(members.assignees.filter(member=>member.role!=="AUDITOR"));
   setWork(tasks.rows);
  }).catch(e=>setError(e instanceof Error?e.message:"Cannot load assignment choices."));
 },[root,canManage]);
 async function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!canManage||busy)return;
  setBusy(true);setError("");setNotice("");
  try{
   await json(url,{method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
     workItemId:workId,recipientUserId:recipient,reason,expiresAt:expires||null
    })});
   setShowRequest(false);setWorkId("");setRecipient("");setReason("");setExpires("");
   setNotice("Assignment request recorded. Ownership has not changed.");
   await load();
  }catch(e){setError(e instanceof Error?e.message:"Cannot create assignment request.");}
  finally{setBusy(false);}
 }
 async function decide(item:Handoff,kind:"ACCEPTED"|"DECLINED"|"CANCELLED"){
  if(busy)return;
  setBusy(true);setError("");setNotice("");
  try{
   await json(url,{method:"PATCH",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(kind==="CANCELLED"?{
     kind:"cancel",handoffId:item.id,revision:item.revision,response:reply[item.id]??""
    }:{
     kind:"decide",handoffId:item.id,revision:item.revision,
     decision:kind,response:reply[item.id]??""
    })});
   setNotice(kind==="ACCEPTED"?
    "You accepted responsibility for this work. Verification remains separate.":
    kind==="DECLINED"?"Handoff declined; ownership is unchanged.":
    "Handoff cancelled; ownership is unchanged.");
   await load();
  }catch(e){setError(e instanceof Error?e.message:"Cannot record decision.");}
  finally{setBusy(false);}
 }
 return <section className="panel">
  <h2>Assignment handoffs</h2>
  <p>Request ownership changes and allow recipients to explicitly accept or decline.
   Until accepted, the current assignee retains responsibility.</p>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  {canManage?<button type="button" onClick={()=>setShowRequest(x=>!x)}>
   {showRequest?"Close request":"Request a work handoff"}
  </button>:null}
  {showRequest&&canManage?<form className="remediation-actions" onSubmit={event=>void submit(event)}>
   <h3>New ownership request</h3>
   <label htmlFor="handoff-work">Work item</label>
   <select id="handoff-work" required value={workId} onChange={event=>setWorkId(event.target.value)}>
    <option value="">Select work item</option>
    {work.map(item=><option value={item.id} key={item.id}>{item.title} ({item.status})</option>)}
   </select>
   <label htmlFor="handoff-recipient">Requested owner</label>
   <select id="handoff-recipient" required value={recipient} onChange={event=>setRecipient(event.target.value)}>
    <option value="">Select member</option>
    {people.map(person=><option value={person.user.id} key={person.user.id}>
     {person.user.name} ({person.role})</option>)}
   </select>
   <label htmlFor="handoff-reason">Why transfer this work?</label>
   <textarea id="handoff-reason" minLength={10} maxLength={2000} required value={reason}
    onChange={event=>setReason(event.target.value)}/>
   <label htmlFor="handoff-expiry">Response deadline (optional, maximum 90 days)</label>
   <input id="handoff-expiry" type="date" value={expires} onChange={event=>setExpires(event.target.value)}/>
   <button type="submit" disabled={busy||!recipient||!workId||reason.trim().length<10}>
    Send assignment request
   </button>
  </form>:null}
  <p><a href={`${url}/export?view=${view}`}>Export the selected handoff history (CSV)</a></p>
  <nav className="remediation-actions" aria-label="Handoff views">
   <label htmlFor="handoff-view">Show requests</label>
   <select id="handoff-view" value={view} onChange={event=>setView(event.target.value as typeof view)}>
    <option value="INBOX">My requests to respond to</option>
    <option value="PENDING">Pending across organization</option>
    <option value="ALL">Recent organization requests</option>
   </select>
   <button type="button" disabled={loading} onClick={()=>void load()}>Refresh requests</button>
  </nav>
  {loading?<p role="status">Loading assignment decisions…</p>:null}
  {model?<div>
   <p>{model.total} matching requests. {model.limited?"Showing the most recent 100.":""}</p>
   <p>{model.summary.awaiting} awaiting responses · {model.summary.expired} expired ·
    {model.summary.accepted} accepted · {model.summary.declined} declined</p>
   <p className="score-caption">{model.disclaimer}</p>
   {!model.rows.length?<p>No requests match this view.</p>:null}
   <ol className="remediation-list">{model.rows.map(item=><li className="remediation-card" key={item.id}>
    <h3>{item.workItem.title}</h3>
    <p><strong>{item.label}</strong> · Requested {date(item.requestedAt)} UTC</p>
    <p>From: {item.requester?.name??"Former member"} ·
     Proposed owner: {item.recipient.name}</p>
    <p>Reason: {item.reason}</p>
    <p>Finding: {item.workItem.finding.title} ({item.workItem.finding.severity},
     {item.workItem.finding.status})</p>
    <p>Work status: {item.workItem.status} · Reply deadline: {date(item.expiresAt)}</p>
    {item.response?<p>Decision note: {item.response}</p>:null}
    {item.decidedAt?<p>Decision recorded: {date(item.decidedAt)} UTC</p>:null}
    {(item.mayDecide||item.mayCancel)?<div className="remediation-actions">
     <label htmlFor={`reply-${item.id}`}>Optional decision note</label>
     <textarea id={`reply-${item.id}`} maxLength={2000}
      value={reply[item.id]??""} onChange={event=>setReply(before=>({
       ...before,[item.id]:event.target.value
      }))}/>
     {item.mayDecide?<div>
      <button type="button" disabled={busy} onClick={()=>void decide(item,"ACCEPTED")}>
       Accept ownership
      </button>
      <button type="button" disabled={busy} onClick={()=>void decide(item,"DECLINED")}>
       Decline request
      </button>
     </div>:null}
     {item.mayCancel?<button type="button" disabled={busy}
      onClick={()=>void decide(item,"CANCELLED")}>Cancel pending request</button>:null}
    </div>:null}
    {item.recipientUserId===userId&&item.status==="ACCEPTED"?
     <p>You accepted this work. Complete the checklist and request independent security verification.</p>:null}
   </li>)}</ol>
  </div>:null}
 </section>;
}
