"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";
type Level="NONE"|"WATCH"|"ELEVATED"|"CRITICAL";
type Reason="OVERDUE"|"DUE_SOON"|"BLOCKED"|"UNASSIGNED"|"URGENT"|"STALE"|"HANDOFF";
type Config={
 scope:"MINE"|"TEAM"|"UNASSIGNED";order:"SEVERITY"|"DEADLINE"|"AGE"|"LAST_UPDATE";
 includeClosed:boolean;thresholdDays:7|14|30|60;
 staleDays:7|14|30|60|90;minLevel:Level;search:string;
};
type Decision={
 id:string;title:string;revision:number;status:string;priority:string;
 assigneeUserId:string|null;assigneeName:string|null;
 dueAt:string|null;updatedAt:string;findingId:string;findingTitle:string;
 findingSeverity:string;findingStatus:string;
 remediationId:string;remediationTitle:string;remediationStatus:string;
 level:Level;score:number;reasons:Reason[];overdueDays:number|null;
 daysUntilDue:number|null;idleDays:number;pendingHandoffs:number;nextAction:string;
};
type Summary={
 total:number;critical:number;elevated:number;watch:number;none:number;
 overdue:number;blocked:number;unassigned:number;stale:number;
 handoff:number;urgent:number;dueSoon:number;
};
type Review={
 generatedAt:string;total:number;summary:Summary;decisions:Decision[];
 coverage:{complete:boolean;maxRecords:number;note:string};
 disclaimer:string;
};
const initial:Config={
 scope:"MINE",order:"SEVERITY",includeClosed:false,thresholdDays:14,
 staleDays:30,minLevel:"WATCH",search:"",
};
const reasonLabels:Record<Reason,string>={
 OVERDUE:"Past target date",DUE_SOON:"Approaching deadline",
 BLOCKED:"Blocked by dependency",UNASSIGNED:"No responsible member",
 URGENT:"Urgent coordination priority",STALE:"No recent recorded update",
 HANDOFF:"Responsibility handoff pending",
};
const levelLabels:Record<Level,string>={
 NONE:"No immediate operational signal",WATCH:"Watch",
 ELEVATED:"Elevated attention",CRITICAL:"Critical attention",
};
function displayDate(value:string|null){
 if(!value)return "No target";
 const d=new Date(value);
 return Number.isNaN(d.getTime())?"Invalid recorded date":d.toISOString().slice(0,10);
}
async function getReview(url:string):Promise<Review>{
 const result=await fetch(url,{cache:"no-store"});
 const body:unknown=await result.json();
 if(!result.ok){
  if(body&&typeof body==="object"&&"error" in body)
   throw new Error(String(body.error));
  throw new Error(`Unable to read escalation review (${result.status}).`);
 }
 return body as Review;
}
export default function EscalationBoard({slug,canManage}:{
 slug:string;canManage:boolean;
}){
 const api=`/api/organizations/${encodeURIComponent(slug)}/actions/work`;
 const [filter,setFilter]=useState<Config>(initial);
 const [model,setModel]=useState<Review|null>(null);
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [loading,setLoading]=useState(false);
 const [refresh,setRefresh]=useState(0);
 const [selected,setSelected]=useState<string[]>([]);
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const [newPriority,setNewPriority]=useState("HIGH");
 const [reason,setReason]=useState("");
 const [preview,setPreview]=useState<{
  ready:boolean;executable:number;decisions:{
   id:string;outcome:string;message:string;current:string|null;proposed:string|null;
  }[];
 }|null>(null);
 const [saving,setSaving]=useState(false);
 const params=new URLSearchParams({
  ...filter,includeClosed:String(filter.includeClosed),
  thresholdDays:String(filter.thresholdDays),staleDays:String(filter.staleDays),
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const result=await getReview(`${api}/escalations?${params.toString()}`);
   setModel(result);setError("");
   setSelected([]);setPreview(null);
  }catch(cause){
   setError(cause instanceof Error?cause.message:"Unable to load escalations.");
  }finally{setLoading(false);}
 // The URL serializes all filter values.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[api,params.toString(),refresh]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Config>(key:K,value:Config[K]){
  setFilter(current=>({...current,[key]:value}));
  setPreview(null);setSelected([]);
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRefresh(current=>current+1);
 }
 function toggle(id:string){
  setSelected(current=>current.includes(id)?
   current.filter(value=>value!==id):[...current,id]);
  setPreview(null);
 }
 function selectLevel(level:Level){
  setSelected(model?.decisions.filter(row=>row.level===level).map(row=>row.id)??[]);
  setPreview(null);
 }
 function changes(){
  return model?.decisions.filter(row=>selected.includes(row.id))
   .map(row=>({id:row.id,revision:row.revision,field:"priority",value:newPriority}))??[];
 }
 async function changePriority(mode:"preview"|"apply"){
  if(!model||!canManage||saving||!selected.length||reason.trim().length<10)return;
  if(mode==="apply"&&!preview?.ready)return;
  setSaving(true);setError("");
  try{
   const response=await fetch(`${api}/batch`,{
    method:"POST",cache:"no-store",headers:{"Content-Type":"application/json"},
    body:JSON.stringify({mode,reason,changes:changes()}),
   });
   const raw:unknown=await response.json();
   if(!response.ok){
    if(raw&&typeof raw==="object"&&"error" in raw)throw new Error(String(raw.error));
    throw new Error("Priority update could not be completed.");
   }
   if(mode==="preview"){
    const next=raw as NonNullable<typeof preview>;
    setPreview(next);
   }else{
    const applied=raw as {changed:number};
    setNotice(`${applied.changed} task priorities recorded. No control was verified.`);
    setSelected([]);setPreview(null);setReason("");
    setRefresh(current=>current+1);
   }
  }catch(cause){
   setPreview(null);
   setError(cause instanceof Error?cause.message:"Failed to update work.");
  }finally{setSaving(false);}
 }
 const chosen=model?.decisions.filter(row=>selected.includes(row.id))??[];
 return <div>
  <section className="panel">
   <h2>Recorded work requiring attention</h2>
   <p>Investigate task delays, missing ownership, blockers and pending handoffs.
    Signals use task records only. They never assert that an organization is secure.</p>
   <p><Link href={`/organizations/${slug}/actions/work/inbox`}>
    Open my ordinary work inbox</Link></p>
  </section>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Attention rules</h2>
   <label htmlFor="escalation-scope">Responsibility scope</label>
   <select id="escalation-scope" value={filter.scope}
    onChange={event=>update("scope",event.target.value as Config["scope"])}>
    <option value="MINE">Assigned to me</option>
    <option value="TEAM">Organization team</option>
    <option value="UNASSIGNED">Unassigned work</option>
   </select>
   <label htmlFor="escalation-order">Review order</label>
   <select id="escalation-order" value={filter.order}
    onChange={event=>update("order",event.target.value as Config["order"])}>
    <option value="SEVERITY">Attention level</option>
    <option value="DEADLINE">Earliest deadline</option>
    <option value="AGE">Longest since update</option>
    <option value="LAST_UPDATE">Oldest update first</option>
   </select>
   <label htmlFor="escalation-minimum">Minimum attention</label>
   <select id="escalation-minimum" value={filter.minLevel}
    onChange={event=>update("minLevel",event.target.value as Level)}>
    <option value="WATCH">Watch or higher</option>
    <option value="ELEVATED">Elevated or critical</option>
    <option value="CRITICAL">Critical only</option>
    <option value="NONE">All tracked work</option>
   </select>
   <label htmlFor="escalation-due">Upcoming deadline window</label>
   <select id="escalation-due" value={filter.thresholdDays}
    onChange={event=>update("thresholdDays",Number(event.target.value) as Config["thresholdDays"])}>
    {[7,14,30,60].map(n=><option key={n} value={n}>{n} days</option>)}
   </select>
   <label htmlFor="escalation-stale">Inactivity threshold</label>
   <select id="escalation-stale" value={filter.staleDays}
    onChange={event=>update("staleDays",Number(event.target.value) as Config["staleDays"])}>
    {[7,14,30,60,90].map(n=><option key={n} value={n}>{n} days</option>)}
   </select>
   <label htmlFor="escalation-search">Search tracked work</label>
   <input id="escalation-search" maxLength={120} value={filter.search}
    onChange={event=>update("search",event.target.value)}/>
   <label><input type="checkbox" checked={filter.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include cancelled or completed tasks</label>
   <button type="submit" disabled={loading}>Refresh escalation review</button>
  </form>
  {model?<div>
   <section className="panel">
    <h2>Current operational attention</h2>
    <p>{model.summary.total} matching task records · {model.total} shown at selected attention threshold.</p>
    <div className="remediation-list">
     <article className="remediation-card"><h3>Critical</h3><p>{model.summary.critical}</p></article>
     <article className="remediation-card"><h3>Elevated</h3><p>{model.summary.elevated}</p></article>
     <article className="remediation-card"><h3>Watch</h3><p>{model.summary.watch}</p></article>
     <article className="remediation-card"><h3>Overdue</h3><p>{model.summary.overdue}</p></article>
     <article className="remediation-card"><h3>Blocked</h3><p>{model.summary.blocked}</p></article>
     <article className="remediation-card"><h3>Unassigned</h3><p>{model.summary.unassigned}</p></article>
     <article className="remediation-card"><h3>Inactive</h3><p>{model.summary.stale}</p></article>
     <article className="remediation-card"><h3>Handoffs</h3><p>{model.summary.handoff}</p></article>
    </div>
    <p className="score-caption">{model.coverage.note}</p>
    <p className="score-caption">{model.disclaimer}</p>
    <div className="remediation-actions">
     <button type="button" onClick={()=>selectLevel("CRITICAL")}>Select critical</button>
     <button type="button" onClick={()=>selectLevel("ELEVATED")}>Select elevated</button>
     <button type="button" onClick={()=>setSelected([])}>Clear selection</button>
    </div>
   </section>
   <section className="panel">
    <h2>Prioritized decisions</h2>
    {!model.decisions.length?<p>No work meets this attention threshold.</p>:null}
    <div className="remediation-list">{model.decisions.map(row=>
     <article className="remediation-card" key={row.id}>
      {canManage?<label><input type="checkbox" checked={selected.includes(row.id)}
       onChange={()=>toggle(row.id)}/> Select work for management review</label>:null}
      <h3>{row.title}</h3>
      <p><strong>{levelLabels[row.level]}</strong> · Attention score {row.score} ·
       {row.priority} work priority · {row.status}</p>
      <p>Responsible: {row.assigneeName??"Unassigned"} ·
       Target: {displayDate(row.dueAt)} ·
       {row.idleDays} days since last recorded update.</p>
      <p>Related finding: {row.findingTitle} ({row.findingSeverity}, {row.findingStatus})</p>
      <p>Remediation: {row.remediationTitle} ({row.remediationStatus})</p>
      <p><strong>Suggested next action:</strong> {row.nextAction}</p>
      <button type="button" aria-expanded={Boolean(expanded[row.id])}
       onClick={()=>setExpanded(current=>({...current,[row.id]:!current[row.id]}))}>
       {expanded[row.id]?"Hide operational signals":"Inspect operational signals"}
      </button>
      {expanded[row.id]?<div>
       <p>Recorded revision: {row.revision} · Updated: {displayDate(row.updatedAt)}</p>
       <ul>{row.reasons.map(reason=><li key={reason}>{reasonLabels[reason]}</li>)}</ul>
       {row.overdueDays!==null?<p>{row.overdueDays} days past target.</p>:null}
       {row.pendingHandoffs>0?<p>{row.pendingHandoffs} pending responsibility handoffs.</p>:null}
       <p>These flags describe work coordination, not independent security evidence.</p>
      </div>:null}
      <p><Link href={`/organizations/${slug}/actions/${row.remediationId}`}>
       Open the underlying remediation</Link></p>
     </article>)}</div>
   </section>
   {canManage?<section className="panel remediation-actions">
    <h2>Coordinated priority changes</h2>
    <p>{selected.length} selected tasks. Owners and admins can record a justified
     work-priority decision, atomically and with revision conflict checks.</p>
    <ul>{chosen.map(row=><li key={row.id}>
     {row.title} · {row.priority} → {newPriority} · revision {row.revision}
    </li>)}</ul>
    <label htmlFor="escalation-priority">Proposed work priority</label>
    <select id="escalation-priority" value={newPriority}
     onChange={event=>{setNewPriority(event.target.value);setPreview(null);}}>
     <option value="LOW">Low</option><option value="NORMAL">Normal</option>
     <option value="HIGH">High</option><option value="URGENT">Urgent</option>
    </select>
    <label htmlFor="escalation-reason">Auditable decision reason</label>
    <textarea id="escalation-reason" required minLength={10} maxLength={1000}
     value={reason} onChange={event=>{setReason(event.target.value);setPreview(null);}}
     placeholder="Explain the reason for adjusting the selected tasks."/>
    {selected.length>50?<p role="alert">At most 50 changes per transaction.</p>:null}
    <button type="button" disabled={saving||!selected.length||
     selected.length>50||reason.trim().length<10}
     onClick={()=>void changePriority("preview")}>Preview change against current revisions</button>
    {preview?<div>
     <h3>Database preflight</h3>
     <p>{preview.executable} executable changes ·
      {preview.ready?"No conflicts found":"Conflicts must be resolved"}.</p>
     <ul>{preview.decisions.map(row=><li key={row.id}>
      {row.id}: {row.outcome} · {row.message} ·
      {row.current??"Unset"} → {row.proposed??"Unset"}
     </li>)}</ul>
     <button type="button" disabled={saving||!preview.ready||!preview.executable}
      onClick={()=>void changePriority("apply")}>Apply reviewed work priorities</button>
    </div>:null}
    <p>A priority change does not alter findings, evidence, remediation execution,
     verification status or CyberScore.</p>
   </section>:null}
  </div>:null}
 </div>;
}
