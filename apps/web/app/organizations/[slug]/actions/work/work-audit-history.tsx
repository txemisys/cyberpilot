"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
type Event={
 id:string;kind:string;occurredAt:string;actorUserId:string|null;
 comment:string|null;before:unknown;after:unknown;
 actor:{name:string;email:string}|null;
};
type Page={
 work:{id:string;title:string;status:string;revision:number};
 page:{rows:Event[];hasMore:boolean;nextCursor:string|null;returned:number};
 filteredRemaining:number;
 statistics:{
  page:{created:number;updated:number;commented:number;reopened:number;other:number;anonymous:number};
  byActor:Array<{actorUserId:string;total:number;comments:number;updates:number}>;
  byDay:Array<{date:string;count:number}>;
 };
 disclaimer:string;
};
const kinds=["ALL","CREATED","UPDATED","COMMENTED","REOPENED"];
function safeDate(value:string){
 const parsed=new Date(value);
 return Number.isNaN(parsed.getTime())?"Unknown date":parsed.toISOString().replace("T"," ").slice(0,19)+" UTC";
}
function pretty(value:unknown){
 if(value===null||value===undefined)return "No snapshot recorded";
 try{return JSON.stringify(value,null,2)??"No snapshot recorded";}
 catch{return "Snapshot cannot be displayed";}
}
async function request<T>(url:string):Promise<T>{
 const response=await fetch(url,{cache:"no-store"});
 const json:unknown=await response.json();
 if(!response.ok){
  if(json&&typeof json==="object"&&"error" in json)
   throw new Error(String((json as {error:unknown}).error));
  throw new Error(`Request failed: ${response.status}`);
 }
 return json as T;
}
export default function WorkAuditHistory({slug,workId}:{slug:string;workId:string}){
 const root=`/api/organizations/${encodeURIComponent(slug)}/actions/work/${encodeURIComponent(workId)}/history`;
 const [kind,setKind]=useState("ALL");
 const [actor,setActor]=useState("");
 const [search,setSearch]=useState("");
 const [limit,setLimit]=useState("25");
 const [cursors,setCursors]=useState<Array<string|null>>([null]);
 const [index,setIndex]=useState(0);
 const [model,setModel]=useState<Page|null>(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const cursor=cursors[index]??null;
 const parameters=new URLSearchParams({
  kind,actor,search,limit,...(cursor?{cursor}:{})
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const data=await request<Page>(`${root}?${parameters}`);
   setModel(data);setError("");
  }catch(e){setError(e instanceof Error?e.message:"Unable to retrieve work events.");}
  finally{setLoading(false);}
 // parameters.toString is an intentional stable dependency on all audit filters.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[root,kind,actor,search,limit,cursor]);
 useEffect(()=>{void load();},[load]);
 function reset(){
  setCursors([null]);setIndex(0);setExpanded({});
 }
 function next(){
  if(!model?.page.hasMore||!model.page.nextCursor)return;
  const nextCursor=model.page.nextCursor;
  setCursors(current=>[...current.slice(0,index+1),nextCursor]);
  setIndex(value=>value+1);
  setExpanded({});
 }
 function previous(){
  if(index<=0)return;
  setIndex(value=>value-1);setExpanded({});
 }
 function apply(event:FormEvent<HTMLFormElement>){
  event.preventDefault();reset();void load();
 }
 function toggle(id:string){setExpanded(value=>({...value,[id]:!value[id]}));}
 const exportUrl=`${root}/export?${parameters}`;
 return <section className="panel" aria-label="Complete work activity history">
  <h2>Complete work audit history</h2>
  <p>Browse older operational decisions, checklist changes, evidence references and comments.
   Activity is attributable but does not establish independent security verification.</p>
  <form className="remediation-actions" onSubmit={apply}>
   <label htmlFor="audit-kind">Event type</label>
   <select id="audit-kind" value={kind} onChange={event=>{setKind(event.target.value);reset();}}>
    {kinds.map(value=><option key={value} value={value}>{value==="ALL"?"All event types":value}</option>)}
   </select>
   <label htmlFor="audit-actor">Actor user ID (optional)</label>
   <input id="audit-actor" value={actor} onChange={event=>{setActor(event.target.value);reset();}}
    maxLength={100} placeholder="Filter one audit actor"/>
   <label htmlFor="audit-search">Search event comments</label>
   <input id="audit-search" value={search} onChange={event=>{setSearch(event.target.value);reset();}}
    maxLength={120} placeholder="Find an action or decision"/>
   <label htmlFor="audit-limit">Events per page</label>
   <select id="audit-limit" value={limit} onChange={event=>{setLimit(event.target.value);reset();}}>
    <option value="10">10</option><option value="25">25</option>
    <option value="50">50</option><option value="100">100</option>
   </select>
   <button type="submit" disabled={loading}>Apply history filters</button>
  </form>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {loading?<p role="status">Loading older work events…</p>:null}
  {model?<div>
   <p><strong>{model.page.returned}</strong> events on page {index+1}.
    {model.page.hasMore?" Additional events available.":" End of the matching history."}</p>
   <p>Page events: {model.statistics.page.created} created ·
    {model.statistics.page.updated} updated ·
    {model.statistics.page.commented} comments ·
    {model.statistics.page.reopened} reopened.</p>
   <p className="score-caption">{model.disclaimer}</p>
   <p><a href={exportUrl}>Export filtered work audit history (CSV; maximum 1,000 events)</a></p>
   <div className="remediation-actions">
    <button type="button" disabled={loading||index===0} onClick={previous}>Newer events</button>
    <button type="button" disabled={loading||!model.page.hasMore} onClick={next}>Older events</button>
    <button type="button" disabled={loading} onClick={()=>void load()}>Refresh history</button>
   </div>
   {!model.page.rows.length?<p>No events match the requested filters.</p>:null}
   <ol className="remediation-list">
    {model.page.rows.map(item=><li key={item.id} className="remediation-card">
     <h3>{item.kind} · {safeDate(item.occurredAt)}</h3>
     <p>Actor: {item.actor?.name??"Former member or system"} ·
      {item.actor?.email??item.actorUserId??"Identity unavailable"}</p>
     <p>{item.comment??"No comment associated with this event."}</p>
     <button type="button" aria-expanded={Boolean(expanded[item.id])}
      onClick={()=>toggle(item.id)}>
      {expanded[item.id]?"Hide change snapshots":"Inspect change snapshots"}
     </button>
     {expanded[item.id]?<div>
      <h4>Before change</h4><pre>{pretty(item.before)}</pre>
      <h4>After change</h4><pre>{pretty(item.after)}</pre>
      <p>These are historical application snapshots, not cryptographic attestations.</p>
     </div>:null}
    </li>)}
   </ol>
   <div className="remediation-actions">
    <button type="button" disabled={loading||index===0} onClick={previous}>Previous page</button>
    <span>Page {index+1}</span>
    <button type="button" disabled={loading||!model.page.hasMore} onClick={next}>Next page</button>
   </div>
   {model.statistics.byActor.length?<details>
    <summary>Activity by actor on this page</summary>
    <ul>{model.statistics.byActor.map(person=><li key={person.actorUserId}>
     {person.actorUserId}: {person.total} events ({person.comments} comments, {person.updates} updates)
    </li>)}</ul>
   </details>:null}
   {model.statistics.byDay.length?<details>
    <summary>Daily activity on this page</summary>
    <ul>{model.statistics.byDay.map(day=><li key={day.date}>{day.date}: {day.count} events</li>)}</ul>
   </details>:null}
  </div>:null}
 </section>;
}
