"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";
type Sort="ATTENTION"|"OVERDUE"|"ACTIVE"|"MEMBER";
type Config={scope:"MINE"|"TEAM";sort:Sort;includeClosed:boolean;
 horizonDays:7|14|30|60;maxTasks:number};
type Task={id:string;title:string;priority:string;status:string;dueAt:string|null;
 daysUntilDue:number|null;attentionPoints:number;reasons:string[]};
type Member={id:string;name:string;role:string;assigned:number;active:number;
 closed:number;urgent:number;blocked:number;overdue:number;upcoming:number;
 stale:number;pendingHandoffs:number;checklistGaps:number;attentionPoints:number;
 tasks:Task[]};
type Summary={members:number;tasks:number;active:number;closed:number;
 assigned:number;unassigned:number;overdue:number;urgent:number;blocked:number;
 upcoming:number;stale:number;pendingHandoffs:number;attentionPoints:number;
 maxActive:number;minActive:number};
type Report={generatedAt:string;members:Member[];unassigned:Member;
 summary:Summary;coverage:{complete:boolean;taskLimit:number;memberLimit:number;
 taskPreviewLimit:number;note:string};disclaimer:string};
const defaults:Config={scope:"MINE",sort:"ATTENTION",includeClosed:false,
 horizonDays:14,maxTasks:10};
const reasonLabels:Record<string,string>={
 OVERDUE:"Past target date",DUE_SOON:"Upcoming target",BLOCKED:"Blocked",
 URGENT:"Urgent",STALE:"No recent update",HANDOFF:"Pending handoff",
 CHECKLIST_GAP:"Checklist incomplete",
};
async function getReport(url:string):Promise<Report>{
 const response=await fetch(url,{cache:"no-store"});
 const body:unknown=await response.json();
 if(!response.ok){
  if(body&&typeof body==="object"&&"error" in body)throw new Error(String(body.error));
  throw new Error(`Capacity request failed (${response.status}).`);
 }
 return body as Report;
}
export default function WorkCapacityBoard({slug}:{slug:string}){
 const [filter,setFilter]=useState<Config>(defaults);
 const [result,setResult]=useState<Report|null>(null);
 const [loading,setLoading]=useState(false);
 const [error,setError]=useState("");
 const [refresh,setRefresh]=useState(0);
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const [onlyAttention,setOnlyAttention]=useState(false);
 const endpoint=`/api/organizations/${encodeURIComponent(slug)}/actions/work/capacity`;
 const params=new URLSearchParams({
  scope:filter.scope,sort:filter.sort,includeClosed:String(filter.includeClosed),
  horizonDays:String(filter.horizonDays),maxTasks:String(filter.maxTasks),
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const report=await getReport(`${endpoint}?${params}`);
   setResult(report);setError("");setExpanded({});
  }catch(cause){setError(cause instanceof Error?cause.message:"Unable to load capacity.");}
  finally{setLoading(false);}
 // Query captures all capacity filters.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[endpoint,params.toString(),refresh]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Config>(key:K,value:Config[K]){
  setFilter(current=>({...current,[key]:value}));
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRefresh(value=>value+1);
 }
 const max=Math.max(1,result?.summary.maxActive??0);
 const people=result?[...result.members,result.unassigned]:[];
 return <div>
  <section className="panel">
   <h2>Real work distribution across members</h2>
   <p>Review assigned operational tasks, overdue work, blockers,
    pending handoffs and checklist gaps. Counts describe currently recorded
    work items, not working hours, employee performance or security coverage.</p>
   <p><Link href={`/organizations/${slug}/actions/work/planning`}>
    Open the explicit assignment planning workflow</Link></p>
  </section>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Workload filters</h2>
   <label htmlFor="capacity-scope">Scope</label>
   <select id="capacity-scope" value={filter.scope}
    onChange={event=>update("scope",event.target.value as Config["scope"])}>
    <option value="MINE">My recorded work</option>
    <option value="TEAM">Entire organization</option>
   </select>
   <label htmlFor="capacity-sort">Sort member loads</label>
   <select id="capacity-sort" value={filter.sort}
    onChange={event=>update("sort",event.target.value as Sort)}>
    <option value="ATTENTION">Highest attention first</option>
    <option value="OVERDUE">Most overdue first</option>
    <option value="ACTIVE">Most active tasks first</option>
    <option value="MEMBER">Member name</option>
   </select>
   <label htmlFor="capacity-days">Upcoming deadline horizon</label>
   <select id="capacity-days" value={filter.horizonDays}
    onChange={event=>update("horizonDays",Number(event.target.value) as Config["horizonDays"])}>
    {[7,14,30,60].map(value=><option key={value} value={value}>{value} days</option>)}
   </select>
   <label htmlFor="capacity-limit">Preview tasks per person</label>
   <select id="capacity-limit" value={filter.maxTasks}
    onChange={event=>update("maxTasks",Number(event.target.value))}>
    {[5,10,20,30,50].map(value=><option key={value} value={value}>{value}</option>)}
   </select>
   <label><input type="checkbox" checked={filter.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include completed and cancelled tasks</label>
   <button type="submit" disabled={loading}>
    {loading?"Loading…":"Refresh workload distribution"}
   </button>
  </form>
  {result?<div>
   <section className="panel">
    <h2>Entire selected work inventory</h2>
    <p>{result.summary.tasks} tasks across {result.summary.members} organization members ·
     {result.summary.active} active · {result.summary.closed} closed.</p>
    <div className="remediation-list">
     {([
      ["assigned","Assigned"],["unassigned","Unassigned or former members"],
      ["overdue","Overdue"],["blocked","Blocked"],["urgent","Urgent"],
      ["upcoming","Due in selected horizon"],["stale","Inactive"],
      ["pendingHandoffs","Pending handoff requests"],
     ] as const).map(([field,title])=><article key={field} className="remediation-card">
      <h3>{title}</h3><p>{result.summary[field]}</p>
     </article>)}
    </div>
    <p>{result.coverage.note}</p>
    <p className="score-caption">{result.disclaimer}</p>
   </section>
   <section className="panel">
    <h2>Recorded member workload</h2>
    <label><input type="checkbox" checked={onlyAttention}
     onChange={event=>setOnlyAttention(event.target.checked)}/>
     Show only tasks with operational attention signals</label>
    <div className="remediation-list">
     {people.map(person=><article key={person.id} className="remediation-card">
      <h3>{person.name}</h3>
      <p>Role: {person.role} · {person.assigned} recorded tasks ·
       {person.active} active · {person.closed} closed.</p>
      <p>Overdue: {person.overdue} · Blocked: {person.blocked} ·
       Urgent: {person.urgent} · Pending handoffs: {person.pendingHandoffs}.</p>
      <p>Operational attention index: {person.attentionPoints}.
       This is a heuristic, not person-hours or an employee score.</p>
      <div aria-label={`Active task distribution: ${person.active} of ${max}`}
       style={{height:10,width:"100%",background:"transparent",border:"1px solid currentColor"}}>
       <div style={{height:"100%",width:`${Math.round(person.active/max*100)}%`,
        background:"currentColor",opacity:0.55}}/>
      </div>
      <button type="button" aria-expanded={Boolean(expanded[person.id])}
       onClick={()=>setExpanded(current=>({...current,[person.id]:!current[person.id]}))}>
       {expanded[person.id]?"Hide task preview":"Inspect highest-attention tasks"}
      </button>
      {expanded[person.id]?<div>
       <p>Showing at most {result.coverage.taskPreviewLimit} tasks per member.
        The summary above still includes every matching task.</p>
       <ul>{person.tasks.filter(task=>!onlyAttention||task.attentionPoints>0)
        .map(task=><li key={task.id}>
         <strong>{task.title}</strong> · {task.priority} · {task.status} ·
         Target: {task.dueAt?.slice(0,10)??"None"}.
         {task.reasons.length?<ul>{task.reasons.map(reason=><li key={reason}>
          {reasonLabels[reason]??reason}</li>)}</ul>:null}
        </li>)}</ul>
       {person.assigned>person.tasks.length?<p>
        {person.assigned-person.tasks.length} additional task records
        are not shown in this preview.</p>:null}
      </div>:null}
     </article>)}
    </div>
   </section>
  </div>:null}
 </div>;
}
