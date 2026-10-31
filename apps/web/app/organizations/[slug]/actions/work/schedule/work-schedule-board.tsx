"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";

type Status="TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE"|"CANCELLED";
type Priority="LOW"|"NORMAL"|"HIGH"|"URGENT";
type ScheduleBucket="OVERDUE"|"TODAY"|"NEXT_7_DAYS"|"LATER"|"UNSCHEDULED"|"CLOSED";
type Entry={
 id:string;title:string;revision:number;status:Status;priority:Priority;
 dueDate:string|null;assigneeUserId:string|null;assigneeName:string|null;
 findingTitle:string;findingSeverity:string;remediationTitle:string;
 remediationStatus:string;bucket:ScheduleBucket;daysUntil:number|null;
 lateBy:number;needsOwner:boolean;isActive:boolean;
};
type Day={
 date:string;items:Entry[];active:number;blocked:number;
 urgent:number;completed:number;unassigned:number;
};
type Summary={
 total:number;active:number;closed:number;overdue:number;today:number;
 dueSoon:number;later:number;unscheduled:number;blocked:number;
 urgent:number;unassigned:number;
};
type Result={
 generatedAt:string;period:{from:string;to:string;days:number};
 summary:Summary;days:Day[];
 overdue:Entry[];unscheduled:Entry[];later:Entry[];closed:Entry[];
 allEntries:Entry[];
 coverage:{complete:boolean;fetched:number;limit:number;message:string};
 disclaimer:string;
};
type Filter={
 range:"WEEK"|"MONTH"|"QUARTER";
 scope:"MINE"|"TEAM"|"UNASSIGNED";
 referenceDate:string;includeClosed:boolean;priority:Priority|"ALL";search:string;
};
type Props={slug:string;canManage:boolean};
const defaultDate=()=>new Date().toISOString().slice(0,10);
function formatDate(value:string|null){return value??"Not scheduled";}
function displayStatus(status:Status){
 return {TODO:"To do",IN_PROGRESS:"In progress",BLOCKED:"Blocked",
  DONE:"Work completed",CANCELLED:"Cancelled"}[status];
}
function bucketLabel(bucket:ScheduleBucket){
 return {OVERDUE:"Overdue",TODAY:"Due today",NEXT_7_DAYS:"Within seven days",
  LATER:"Later deadline",UNSCHEDULED:"No date",CLOSED:"Work closed"}[bucket];
}
function dateOffset(value:string,days:number){
 const date=new Date(value+"T12:00:00Z");
 date.setUTCDate(date.getUTCDate()+days);
 return date.toISOString().slice(0,10);
}
async function loadJson<T>(url:string,init?:RequestInit):Promise<T>{
 const response=await fetch(url,{...init,cache:"no-store",
  headers:{"Content-Type":"application/json",...init?.headers}});
 const payload:unknown=await response.json();
 if(!response.ok){
  if(payload&&typeof payload==="object"&&"error" in payload)
   throw new Error(String(payload.error));
  throw new Error(`Request failed (${response.status}).`);
 }
 return payload as T;
}
export default function WorkScheduleBoard({slug,canManage}:Props){
 const base=`/api/organizations/${encodeURIComponent(slug)}/actions/work`;
 const [filter,setFilter]=useState<Filter>({
  range:"MONTH",scope:"MINE",referenceDate:defaultDate(),
  includeClosed:false,priority:"ALL",search:"",
 });
 const [result,setResult]=useState<Result|null>(null);
 const [loading,setLoading]=useState(false);
 const [saving,setSaving]=useState(false);
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [revision,setRevision]=useState(0);
 const [selectedDay,setSelectedDay]=useState<string|null>(null);
 const [selectedIds,setSelectedIds]=useState<string[]>([]);
 const [newDate,setNewDate]=useState("");
 const [reason,setReason]=useState("");
 const [preview,setPreview]=useState<{
  ready:boolean;executable:number;decisions:{
   id:string;outcome:string;message:string;current:string|null;proposed:string|null;
  }[];
 }|null>(null);
 const params=new URLSearchParams({...filter,
  includeClosed:String(filter.includeClosed),
 });
 const endpoint=`${base}/schedule?${params.toString()}`;
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const response=await loadJson<Result>(endpoint);
   setResult(response);setError("");
   setSelectedIds([]);setPreview(null);
  }catch(cause){
   setError(cause instanceof Error?cause.message:"Failed to load schedule.");
  }finally{setLoading(false);}
 },[endpoint,revision]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Filter>(field:K,value:Filter[K]){
  setFilter(current=>({...current,[field]:value}));
  setPreview(null);setNotice("");
 }
 function navigate(days:number){
  update("referenceDate",dateOffset(filter.referenceDate,days));
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRevision(current=>current+1);
 }
 function toggle(id:string){
  setSelectedIds(current=>current.includes(id)?
   current.filter(value=>value!==id):[...current,id]);
  setPreview(null);
 }
 function selectAll(items:Entry[]){
  setSelectedIds(items.filter(item=>item.isActive).map(item=>item.id));
  setPreview(null);
 }
 function changes(){
  return result?.allEntries.filter(item=>selectedIds.includes(item.id))
   .map(item=>({
    id:item.id,revision:item.revision,field:"dueAt",
    value:newDate||null,
   }))??[];
 }
 async function perform(mode:"preview"|"apply"){
  if(!result||saving||!canManage||!selectedIds.length||reason.trim().length<10)return;
  setSaving(true);setError("");
  try{
   const response=await loadJson<{
    ready?:boolean;executable?:number;
    decisions?:{id:string;outcome:string;message:string;current:string|null;proposed:string|null}[];
    changed?:number;
   }>(`${base}/batch`,{
    method:"POST",
    body:JSON.stringify({mode,reason,changes:changes()}),
   });
   if(mode==="preview"){
    setPreview({
     ready:response.ready??false,executable:response.executable??0,
     decisions:response.decisions??[],
    });
   }else{
    setNotice(`${response.changed??0} work deadlines updated. No security status changed.`);
    setPreview(null);setSelectedIds([]);setReason("");setNewDate("");
    setRevision(current=>current+1);
   }
  }catch(cause){
   setPreview(null);
   setError(cause instanceof Error?cause.message:"Unable to update dates.");
  }finally{setSaving(false);}
 }
 const currentDay=result?.days.find(day=>day.date===selectedDay);
 const visibleDates=result?.days??[];
 const selectedItems=result?.allEntries.filter(item=>selectedIds.includes(item.id))??[];
 const nextDays=filter.range==="WEEK"?7:filter.range==="MONTH"?30:90;
 return <div>
  <section className="panel">
   <h2>Recorded remediation target dates</h2>
   <p>Review who is expected to do human work, which tasks are overdue,
    and which have no target date. Calendar entries are task deadlines,
    not proof that any security control works.</p>
   <p><Link href={`/organizations/${slug}/actions/work`}>
    Return to detailed work coordination</Link></p>
  </section>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Schedule filters</h2>
   <label htmlFor="schedule-range">Calendar period</label>
   <select id="schedule-range" value={filter.range}
    onChange={event=>update("range",event.target.value as Filter["range"])}>
    <option value="WEEK">Week</option>
    <option value="MONTH">Month</option>
    <option value="QUARTER">Quarter</option>
   </select>
   <label htmlFor="schedule-scope">Task ownership</label>
   <select id="schedule-scope" value={filter.scope}
    onChange={event=>update("scope",event.target.value as Filter["scope"])}>
    <option value="MINE">My tasks</option>
    <option value="TEAM">Organization team</option>
    <option value="UNASSIGNED">Unassigned</option>
   </select>
   <label htmlFor="schedule-reference">Reference date</label>
   <input type="date" id="schedule-reference" value={filter.referenceDate}
    onChange={event=>update("referenceDate",event.target.value)}/>
   <label htmlFor="schedule-priority">Priority</label>
   <select id="schedule-priority" value={filter.priority}
    onChange={event=>update("priority",event.target.value as Filter["priority"])}>
    <option value="ALL">All priorities</option>
    {(["LOW","NORMAL","HIGH","URGENT"] as Priority[]).map(value=>
     <option key={value}>{value}</option>)}
   </select>
   <label htmlFor="schedule-search">Find work</label>
   <input type="search" id="schedule-search" maxLength={120}
    value={filter.search} onChange={event=>update("search",event.target.value)}/>
   <label><input type="checkbox" checked={filter.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include completed and cancelled work</label>
   <button type="submit" disabled={loading}>{loading?"Loading…":"Refresh schedule"}</button>
  </form>
  {result?<div>
   <section className="panel">
    <h2>Coverage and workload</h2>
    <p>{result.period.from} through {result.period.to} ·
     {result.coverage.fetched} matching work records.</p>
    <p>{result.coverage.message}</p>
    <div className="remediation-list">
     <article className="remediation-card"><h3>Open tasks</h3><p>{result.summary.active}</p></article>
     <article className="remediation-card"><h3>Overdue</h3><p>{result.summary.overdue}</p></article>
     <article className="remediation-card"><h3>Due today</h3><p>{result.summary.today}</p></article>
     <article className="remediation-card"><h3>Within seven days</h3><p>{result.summary.dueSoon}</p></article>
     <article className="remediation-card"><h3>No date</h3><p>{result.summary.unscheduled}</p></article>
     <article className="remediation-card"><h3>Blocked</h3><p>{result.summary.blocked}</p></article>
     <article className="remediation-card"><h3>Unassigned</h3><p>{result.summary.unassigned}</p></article>
    </div>
    <p><a href={`${endpoint}&format=ics`}>
     Download recorded deadlines (.ics calendar file)</a></p>
    <p className="score-caption">{result.disclaimer}</p>
   </section>
   <section className="panel">
    <h2>Schedule by day</h2>
    <div className="remediation-actions">
     <button type="button" onClick={()=>navigate(-nextDays)}>Previous period</button>
     <button type="button" onClick={()=>update("referenceDate",defaultDate())}>Current period</button>
     <button type="button" onClick={()=>navigate(nextDays)}>Next period</button>
    </div>
    <div className="remediation-list">
     {visibleDates.map(day=><article className="remediation-card" key={day.date}>
      <h3>{day.date}</h3>
      <p>{day.active} active targets · {day.urgent} urgent ·
       {day.blocked} blocked · {day.completed} closed</p>
      <button type="button" aria-expanded={selectedDay===day.date}
       onClick={()=>setSelectedDay(current=>current===day.date?null:day.date)}>
       {selectedDay===day.date?"Hide tasks":"View dated tasks"}
      </button>
      {selectedDay===day.date?<div>
       {!day.items.length?<p>No recorded target dates.</p>:null}
       <ul>{day.items.map(item=><li key={item.id}>
        {item.title} · {item.priority} · {displayStatus(item.status)}
       </li>)}</ul>
       {canManage?<button type="button" onClick={()=>selectAll(day.items)}>
        Select active tasks for rescheduling</button>:null}
      </div>:null}
     </article>)}
    </div>
   </section>
   {(["overdue","unscheduled","later"] as const).map(section=><section
    className="panel" key={section}>
    <h2>{section==="overdue"?"Overdue work":section==="unscheduled"?
     "Work without a deadline":"Work after the visible period"}</h2>
    <p>{result[section].length} matching tasks.</p>
    {!result[section].length?<p>No tasks in this category.</p>:null}
    <div className="remediation-list">{result[section].map(item=>
     <article className="remediation-card" key={item.id}>
      <h3>{item.title}</h3>
      <p>{bucketLabel(item.bucket)} · {item.priority} ·
       {displayStatus(item.status)} · {formatDate(item.dueDate)}</p>
      <p>Responsible: {item.assigneeName??"Unassigned"} ·
       Finding: {item.findingTitle} ({item.findingSeverity})</p>
      {canManage&&item.isActive?<label>
       <input type="checkbox" checked={selectedIds.includes(item.id)}
        onChange={()=>toggle(item.id)}/> Select for coordinated rescheduling
      </label>:null}
     </article>)}</div>
    {canManage&&result[section].length?<button type="button"
     onClick={()=>selectAll(result[section])}>Select active tasks in this category</button>:null}
   </section>)}
   {canManage?<section className="panel remediation-actions">
    <h2>Reschedule selected work</h2>
    <p>{selectedIds.length} selected work items.
     Deadline changes are recorded transactionally with revision checks.</p>
    <ul>{selectedItems.map(item=><li key={item.id}>
     {item.title} · {item.dueDate??"No date"} · revision {item.revision}
    </li>)}</ul>
    <label htmlFor="schedule-new-date">New target date (blank clears deadline)</label>
    <input type="date" id="schedule-new-date" value={newDate}
     onChange={event=>{setNewDate(event.target.value);setPreview(null);}}/>
    <label htmlFor="schedule-reason">Reason for changing targets</label>
    <textarea id="schedule-reason" required minLength={10} maxLength={1000}
     value={reason} onChange={event=>{setReason(event.target.value);setPreview(null);}}
     placeholder="Explain why the work deadlines need to change."/>
    <button type="button" disabled={saving||selectedIds.length===0||
     selectedIds.length>50||reason.trim().length<10}
     onClick={()=>void perform("preview")}>Preview rescheduling changes</button>
    {selectedIds.length>50?<p role="alert">
     Select no more than 50 work items per transaction.</p>:null}
    {preview?<div>
     <h3>Revision and permission review</h3>
     <p>{preview.executable} executable changes ·
      {preview.ready?"All selected rows valid":"Resolve conflicts before applying"}.</p>
     <ul>{preview.decisions.map(row=><li key={row.id}>
      {row.id} · {row.outcome}: {row.message} ·
      {row.current??"No date"} → {row.proposed??"No date"}
     </li>)}</ul>
     <button type="button" disabled={saving||!preview.ready||!preview.executable}
      onClick={()=>void perform("apply")}>Apply reviewed dates atomically</button>
    </div>:null}
    <p>Changing a task deadline does not alter the finding, remediation execution,
     recorded evidence, verification or CyberScore.</p>
   </section>:null}
   {currentDay?<p className="score-caption">Selected calendar day: {currentDay.date}.
    The calendar shows target dates recorded by users.</p>:null}
  </div>:null}
 </div>;
}
