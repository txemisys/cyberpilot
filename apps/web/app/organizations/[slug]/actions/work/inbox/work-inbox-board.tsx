"use client";

import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";

type Attention="CRITICAL"|"HIGH"|"NORMAL"|"LOW"|"CLOSED";
type Filter={
 view:"MINE"|"TEAM"|"UNASSIGNED"|"HANDOFFS";
 urgency:"ALL"|"OVERDUE"|"DUE_SOON"|"BLOCKED"|"URGENT"|"NO_DATE";
 sort:"ATTENTION"|"DUE"|"UPDATED"|"PRIORITY";
 search:string;includeClosed:boolean;page:number;pageSize:number;
};
type InboxRow={
 id:string;title:string;description:string;status:string;priority:string;
 revision:number;dueAt:string|null;updatedAt:string;
 assigneeUserId:string|null;assigneeName:string|null;
 findingTitle:string;findingSeverity:string;findingStatus:string;
 remediationTitle:string;remediationStatus:string;attention:Attention;
 attentionReasons:string[];ageDays:number;dueDays:number|null;
 handoffCount:number;pendingForMe:number;handoffExpiresSoon:boolean;
 proposedNextAction:string;
};
type Summary={
 total:number;open:number;blocked:number;overdue:number;dueSoon:number;
 urgent:number;unassigned:number;closed:number;pendingHandoffs:number;
 attention:Record<Attention,number>;
};
type Handoff={
 id:string;workItemId:string;title:string;reason:string;
 requestedAt:string;expiresAt:string|null;
};
type Inbox={
 filter:Filter;page:number;pages:number;pageSize:number;total:number;
 rows:InboxRow[];summary:Summary;
 handoffs:{
  pendingForMe:number;expiringSoon:number;rows:Handoff[];truncated:boolean;
 };
 coverage:{summaryScope:string;resultScope:string;snapshotAt:string;note:string};
};
const defaultFilter:Filter={
 view:"MINE",urgency:"ALL",sort:"ATTENTION",
 search:"",includeClosed:false,page:1,pageSize:20,
};
const attentionLabels:Record<Attention,string>={
 CRITICAL:"Immediate review",HIGH:"High attention",NORMAL:"Routine attention",
 LOW:"Monitor",CLOSED:"Closed work record",
};
function date(value:string|null){
 if(!value)return "No target date";
 const parsed=new Date(value);
 return Number.isNaN(parsed.getTime())?"Unknown date":parsed.toISOString().slice(0,10);
}
async function getInbox(url:string):Promise<Inbox>{
 const response=await fetch(url,{cache:"no-store"});
 const body:unknown=await response.json();
 if(!response.ok){
  if(body&&typeof body==="object"&&"error" in body)
   throw new Error(String(body.error));
  throw new Error(`Could not load inbox (${response.status}).`);
 }
 return body as Inbox;
}
export default function WorkInboxBoard({slug,currentUserId}:{
 slug:string;currentUserId:string;
}){
 const endpoint=`/api/organizations/${encodeURIComponent(slug)}/actions/work/inbox`;
 const [filter,setFilter]=useState<Filter>(defaultFilter);
 const [inbox,setInbox]=useState<Inbox|null>(null);
 const [loading,setLoading]=useState(false);
 const [error,setError]=useState("");
 const [refresh,setRefresh]=useState(0);
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const [selected,setSelected]=useState<string[]>([]);
 const [onlySelected,setOnlySelected]=useState(false);
 const base=`/organizations/${slug}/actions/work`;
 const query=new URLSearchParams({
  view:filter.view,urgency:filter.urgency,sort:filter.sort,
  search:filter.search,includeClosed:String(filter.includeClosed),
  page:String(filter.page),pageSize:String(filter.pageSize),
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const data=await getInbox(`${endpoint}?${query.toString()}`);
   setInbox(data);setError("");
  }catch(cause){
   setError(cause instanceof Error?cause.message:"Unable to load inbox.");
  }finally{setLoading(false);}
 // Filter fields are all serialized in query.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[endpoint,query.toString(),refresh]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Filter>(key:K,value:Filter[K]){
  setFilter(current=>({...current,[key]:value,page:1}));
  setExpanded({});setSelected([]);
 }
 function apply(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRefresh(value=>value+1);
 }
 function toggle(id:string){
  setExpanded(current=>({...current,[id]:!current[id]}));
 }
 function choose(id:string){
  setSelected(current=>current.includes(id)
   ?current.filter(value=>value!==id):[...current,id]);
 }
 function chooseAll(){
  setSelected(inbox?.rows.map(row=>row.id)??[]);
 }
 const displayed=inbox?.rows.filter(row=>!onlySelected||selected.includes(row.id))??[];
 return <div>
  <section className="panel">
   <h2>My operational attention queue</h2>
   <p>One workspace for assignments, deadlines, blockers and handoff requests.
    This view reads recorded work. It does not execute remediations,
    independently test a control or mark a finding resolved.</p>
   <p>Signed-in user reference: {currentUserId}</p>
   <p><Link href={base}>Manage individual work items</Link></p>
  </section>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  <form className="panel remediation-actions" onSubmit={apply}>
   <h2>Filter operational work</h2>
   <label htmlFor="inbox-view">Whose work</label>
   <select id="inbox-view" value={filter.view}
    onChange={event=>update("view",event.target.value as Filter["view"])}>
    <option value="MINE">Assigned to me</option>
    <option value="TEAM">All organization work</option>
    <option value="UNASSIGNED">Unassigned work</option>
    <option value="HANDOFFS">Handoffs awaiting my decision</option>
   </select>
   <label htmlFor="inbox-urgency">Attention filter</label>
   <select id="inbox-urgency" value={filter.urgency}
    onChange={event=>update("urgency",event.target.value as Filter["urgency"])}>
    <option value="ALL">All attention levels</option>
    <option value="OVERDUE">Overdue work</option>
    <option value="DUE_SOON">Due in seven days</option>
    <option value="BLOCKED">Blocked work</option>
    <option value="URGENT">Urgent priority</option>
    <option value="NO_DATE">Without a target date</option>
   </select>
   <label htmlFor="inbox-sort">Sort by</label>
   <select id="inbox-sort" value={filter.sort}
    onChange={event=>update("sort",event.target.value as Filter["sort"])}>
    <option value="ATTENTION">Attention first</option>
    <option value="DUE">Earliest target first</option>
    <option value="PRIORITY">Highest priority first</option>
    <option value="UPDATED">Recent changes first</option>
   </select>
   <label htmlFor="inbox-search">Search tasks and findings</label>
   <input id="inbox-search" type="search" maxLength={100}
    value={filter.search} onChange={event=>update("search",event.target.value)}
    placeholder="Task, finding or remediation"/>
   <label htmlFor="inbox-size">Rows per page</label>
   <select id="inbox-size" value={filter.pageSize}
    onChange={event=>update("pageSize",Number(event.target.value))}>
    <option value={20}>20</option><option value={50}>50</option>
    <option value={100}>100</option>
   </select>
   <label><input type="checkbox" checked={filter.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include completed and cancelled work (not verified findings)</label>
   <button type="submit" disabled={loading}>
    {loading?"Loading…":"Refresh filtered work"}
   </button>
  </form>
  {inbox?<div>
   <section className="panel">
    <h2>Matching work at a glance</h2>
    <p>{inbox.total} matching tasks · {inbox.summary.open} open ·
     {inbox.summary.closed} completed or cancelled.</p>
    <div className="remediation-list">
     <div className="remediation-card">
      <h3>Past target date</h3><p>{inbox.summary.overdue}</p>
     </div>
     <div className="remediation-card">
      <h3>Blocked</h3><p>{inbox.summary.blocked}</p>
     </div>
     <div className="remediation-card">
      <h3>Due in seven days</h3><p>{inbox.summary.dueSoon}</p>
     </div>
     <div className="remediation-card">
      <h3>Urgent work</h3><p>{inbox.summary.urgent}</p>
     </div>
     <div className="remediation-card">
      <h3>Without assignee</h3><p>{inbox.summary.unassigned}</p>
     </div>
     <div className="remediation-card">
      <h3>Pending handoffs</h3><p>{inbox.handoffs.pendingForMe}</p>
     </div>
    </div>
    <p>{inbox.summary.attention.CRITICAL} immediate ·
     {inbox.summary.attention.HIGH} high ·
     {inbox.summary.attention.NORMAL} routine ·
     {inbox.summary.attention.LOW} monitor.</p>
    <p className="score-caption">Counts are scoped to the complete matching
     work filter, not just this page. Attention is operational priority,
     not a live risk score or security certification.</p>
   </section>
   <section className="panel">
    <h2>Incoming responsibility handoffs</h2>
    <p>{inbox.handoffs.pendingForMe} awaiting your decision,
     {inbox.handoffs.expiringSoon} approaching or past their deadline.</p>
    {inbox.handoffs.truncated?<p className="permission-warning">
     Only the 100 newest pending handoffs are listed here.</p>:null}
    {!inbox.handoffs.rows.length?<p>No pending handoff requests.</p>:null}
    <div className="remediation-list">
     {inbox.handoffs.rows.map(row=><article key={row.id}
      className="remediation-card">
      <h3>{row.title}</h3>
      <p>Requested: {date(row.requestedAt)} ·
       Expires: {date(row.expiresAt)}</p>
      <p>{row.reason}</p>
      <p><Link href={base}>Review the handoff decision in work coordination</Link></p>
     </article>)}
    </div>
   </section>
   <section className="panel">
    <h2>Prioritized work queue</h2>
    <p>{inbox.rows.length} tasks on this page · page {inbox.page} of {inbox.pages}.</p>
    <p>{selected.length} selected locally. Selection is for review only;
     it does not perform any changes.</p>
    <div className="remediation-actions">
     <button type="button" onClick={chooseAll}>Select visible page</button>
     <button type="button" onClick={()=>setSelected([])}>Clear selection</button>
     <label><input type="checkbox" checked={onlySelected}
      onChange={event=>setOnlySelected(event.target.checked)}/>
      Show only selected rows</label>
    </div>
    {!displayed.length?<p>No work matches this selection.</p>:null}
    <div className="remediation-list">
     {displayed.map(item=><article className="remediation-card" key={item.id}>
      <label><input type="checkbox" checked={selected.includes(item.id)}
       onChange={()=>choose(item.id)}/>
       <strong>{item.title}</strong></label>
      <h3>{attentionLabels[item.attention]}</h3>
      <p>{item.priority} priority · {item.status} work ·
       Finding severity: {item.findingSeverity}</p>
      <p>Responsible: {item.assigneeName??"Unassigned"} ·
       Target: {date(item.dueAt)} ·
       {item.dueDays===null?"No due date":item.dueDays<0
        ?`${Math.abs(item.dueDays)} days overdue`
        :`${item.dueDays} days remaining`}</p>
      <p>Related finding: {item.findingTitle} ({item.findingStatus})</p>
      <p>Remediation: {item.remediationTitle} ({item.remediationStatus})</p>
      {item.pendingForMe>0?<p className="permission-warning">
       {item.pendingForMe} requested handoffs await your decision.</p>:null}
      <p><strong>Next operational step:</strong> {item.proposedNextAction}</p>
      <button type="button" aria-expanded={Boolean(expanded[item.id])}
       onClick={()=>toggle(item.id)}>
       {expanded[item.id]?"Hide context":"Review attention context"}
      </button>
      {expanded[item.id]?<div>
       <p>{item.description||"No additional work instructions recorded."}</p>
       <p>Created {item.ageDays} days ago · revision {item.revision} ·
        Last updated {date(item.updatedAt)}.</p>
       {item.attentionReasons.length?<ul>{item.attentionReasons.map(reason=>
        <li key={reason}>{reason}</li>)}</ul>:<p>No special attention flags.</p>}
       <p>Priority indicators are based on recorded work metadata,
        not independent evidence of security control effectiveness.</p>
      </div>:null}
      <p><Link href={base}>Open work tracking and history</Link></p>
     </article>)}
    </div>
    <nav aria-label="Work inbox pagination">
     <button type="button" disabled={loading||inbox.page<=1}
      onClick={()=>setFilter(current=>({...current,page:current.page-1}))}>
      Previous page</button>
     <span> Page {inbox.page} / {inbox.pages} </span>
     <button type="button" disabled={loading||inbox.page>=inbox.pages}
      onClick={()=>setFilter(current=>({...current,page:current.page+1}))}>
      Next page</button>
    </nav>
   </section>
   <p className="score-caption">{inbox.coverage.note}
    Snapshot reference: {date(inbox.coverage.snapshotAt)}.</p>
  </div>:null}
 </div>;
}
