"use client";
import {useCallback,useEffect,useState} from "react";
type Event={eventId:string;workItemId:string;kind:string;at:string;title:string;
 actor:string|null;findingStatus:string;workStatus:string;comment:string|null;
 warning:string|null};
type Activity={
 total:number;limited:boolean;events:Event[];
 concerns:{total:number;anonymous:number;completedWorkOpenFindings:number;
  comments:number;updates:number;distinctTasks:number;disclaimer:string};
 byWork:Array<{workItemId:string;title:string;events:number;comments:number;
  lastAt:string;findingStatus:string;workStatus:string}>;
 disclaimer:string;
};
async function loadActivity(url:string):Promise<Activity>{
 const response=await fetch(url,{cache:"no-store"});
 const result:unknown=await response.json();
 if(!response.ok){
  if(result&&typeof result==="object"&&"error" in result)
   throw new Error(String((result as {error:unknown}).error));
  throw new Error(`Request failed: ${response.status}`);
 }
 return result as Activity;
}
export default function WorkOrganizationActivity({slug}:{slug:string}){
 const [days,setDays]=useState("30");
 const [kind,setKind]=useState("ALL");
 const [limit,setLimit]=useState("25");
 const [activity,setActivity]=useState<Activity|null>(null);
 const [loading,setLoading]=useState(false);
 const [error,setError]=useState("");
 const query=new URLSearchParams({days,kind,limit});
 const url=`/api/organizations/${encodeURIComponent(slug)}/actions/work/activity?${query}`;
 const load=useCallback(async()=>{
  setLoading(true);
  try{setActivity(await loadActivity(url));setError("");}
  catch(e){setError(e instanceof Error?e.message:"Cannot retrieve work activity.");}
  finally{setLoading(false);}
 },[url]);
 useEffect(()=>{void load();},[load]);
 return <section className="panel">
  <h2>Recent organization work activity</h2>
  <p>Review operational changes across tasks to identify work that may require additional attention.</p>
  <div className="remediation-actions">
   <label htmlFor="feed-days">Time window</label>
   <select id="feed-days" value={days} onChange={event=>setDays(event.target.value)}>
    <option value="7">Last 7 days</option><option value="30">Last 30 days</option>
    <option value="90">Last 90 days</option>
   </select>
   <label htmlFor="feed-kind">Event category</label>
   <select id="feed-kind" value={kind} onChange={event=>setKind(event.target.value)}>
    <option value="ALL">All changes</option><option value="CREATED">Created</option>
    <option value="UPDATED">Updated</option><option value="COMMENTED">Comments</option>
    <option value="REOPENED">Reopened</option>
   </select>
   <label htmlFor="feed-limit">Show at most</label>
   <select id="feed-limit" value={limit} onChange={event=>setLimit(event.target.value)}>
    <option value="10">10 events</option><option value="25">25 events</option>
    <option value="50">50 events</option><option value="100">100 events</option>
   </select>
   <button type="button" onClick={()=>void load()} disabled={loading}>Refresh activity</button>
  </div>
  {loading?<p role="status">Retrieving organization work activity…</p>:null}
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {activity?<div>
   <p><strong>{activity.total}</strong> matching activity records.
    {activity.limited?" Displaying the most recent selected records.":""}</p>
   <p>{activity.concerns.distinctTasks} distinct tasks ·
    {activity.concerns.comments} comments ·
    {activity.concerns.updates} updates on the displayed activity.</p>
   {activity.concerns.completedWorkOpenFindings>0?<p>
    {activity.concerns.completedWorkOpenFindings} events concern work currently marked
    completed while its finding remains open. Review verification separately.
   </p>:null}
   <p className="score-caption">{activity.disclaimer}</p>
   {!activity.events.length?<p>No recorded work activity matches this window.</p>:null}
   <ol className="remediation-list">
    {activity.events.map(item=><li key={item.eventId} className="remediation-card">
     <h3>{item.title}</h3>
     <p>{item.kind} · {new Date(item.at).toISOString().slice(0,16).replace("T"," ")} UTC</p>
     <p>Actor: {item.actor??"Former member or system"}</p>
     <p>Work: {item.workStatus} · Finding: {item.findingStatus}</p>
     {item.comment?<p>{item.comment}</p>:null}
     {item.warning?<p>{item.warning}</p>:null}
    </li>)}
   </ol>
   {activity.byWork.length?<details>
    <summary>Activity volume by work item</summary>
    <ul>{activity.byWork.map(item=><li key={item.workItemId}>
     {item.title}: {item.events} events, {item.comments} comments;
     work {item.workStatus}, finding {item.findingStatus}
    </li>)}</ul>
   </details>:null}
  </div>:null}
 </section>;
}
