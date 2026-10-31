"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";
type Metric="ALL"|"CREATED"|"COMPLETED"|"REOPENED"|"OWNERSHIP"|"DEADLINE"|"PRIORITY";
type Filter={days:7|14|30|60|90;scope:"MINE"|"TEAM";metric:Metric;
 includeComments:boolean;includeChecklist:boolean};
type Category=Exclude<Metric,"ALL">|"COMMENT"|"CHECKLIST"|"OTHER"|"UNKNOWN";
type Activity={id:string;workItemId:string;occurredAt:string;actorUserId:string|null;
 category:Category;label:string;confidence:"EXPLICIT"|"SNAPSHOT"|"UNKNOWN";
 from:string|null;to:string|null};
type Day={date:string;created:number;completed:number;reopened:number;ownership:number;
 deadline:number;priority:number;comments:number;checklist:number;other:number;
 unknown:number;total:number};
type Summary={totalEvents:number;created:number;completed:number;reopened:number;
 ownership:number;deadline:number;priority:number;comments:number;checklist:number;
 other:number;unknown:number;affectedWork:number;actors:number;openNow:number;
 doneNow:number;overdueNow:number;unassignedNow:number};
type Trends={from:string;to:string;generatedAt:string;days:Day[];
 events:Activity[];summary:Summary;coverage:{
 complete:boolean;workCount:number;eventCount:number;workLimit:number;
 eventLimit:number;note:string};disclaimer:string};
const initial:Filter={days:30,scope:"MINE",metric:"ALL",
 includeComments:true,includeChecklist:true};
const names:Record<Category,string>={
 CREATED:"Created",COMPLETED:"Marked complete",REOPENED:"Reopened",
 OWNERSHIP:"Ownership change",DEADLINE:"Deadline change",
 PRIORITY:"Priority change",COMMENT:"Comment",CHECKLIST:"Checklist",
 OTHER:"Other update",UNKNOWN:"Unclassified",
};
function escapeCsv(value:string){
 const safe=/^\s*[=+@-]/.test(value)?"'"+value:value;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function activityCsv(items:Activity[]){
 const lines=[["Work item","Occurred UTC","Category","Actor","Source quality","Previous","New"]];
 for(const item of items)lines.push([item.workItemId,item.occurredAt,item.category,
  item.actorUserId??"",item.confidence,item.from??"",item.to??""]);
 return lines.map(line=>line.map(escapeCsv).join(",")).join("\r\n")+"\r\n";
}
async function fetchTrends(url:string):Promise<Trends>{
 const result=await fetch(url,{cache:"no-store"});
 const payload:unknown=await result.json();
 if(!result.ok){
  if(payload&&typeof payload==="object"&&"error" in payload)
   throw new Error(String(payload.error));
  throw new Error(`Request failed (${result.status}).`);
 }
 return payload as Trends;
}
export default function WorkTrendsBoard({slug}:{slug:string}){
 const root=`/api/organizations/${encodeURIComponent(slug)}/actions/work/trends`;
 const [filter,setFilter]=useState<Filter>(initial);
 const [result,setResult]=useState<Trends|null>(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [refresh,setRefresh]=useState(0);
 const [visible,setVisible]=useState(20);
 const [selectedDay,setSelectedDay]=useState<string|null>(null);
 const [showDetails,setShowDetails]=useState(false);
 const query=new URLSearchParams({
  days:String(filter.days),scope:filter.scope,metric:filter.metric,
  includeComments:String(filter.includeComments),
  includeChecklist:String(filter.includeChecklist),
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const next=await fetchTrends(`${root}?${query}`);
   setResult(next);setError("");setVisible(20);
  }catch(cause){setError(cause instanceof Error?cause.message:"Unable to read trends.");}
  finally{setLoading(false);}
 // The serialized filter is a complete stable request key.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[root,query.toString(),refresh]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Filter>(field:K,value:Filter[K]){
  setFilter(current=>({...current,[field]:value}));
  setSelectedDay(null);
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRefresh(current=>current+1);
 }
 function download(){
  if(!result)return;
  const file=activityCsv(result.events);
  // The browser download is triggered by the user's explicit click.
  const blob=new Blob([file],{type:"text/csv;charset=utf-8"});
  const url=URL.createObjectURL(blob);
  const anchor=document.createElement("a");
  anchor.href=url;anchor.download="cyberpilot-work-activity.csv";
  anchor.click();URL.revokeObjectURL(url);
 }
 const rows=selectedDay?result?.events.filter(event=>
  event.occurredAt.startsWith(selectedDay))??[]:result?.events??[];
 const peak=Math.max(1,...(result?.days.map(day=>day.total)??[]));
 return <div>
  <section className="panel">
   <h2>Operational event history</h2>
   <p>This timeline uses persisted work events and recorded before/after snapshots.
    Unknown historical changes stay unclassified instead of being inferred.</p>
   <p>It does not measure scanner execution, remediation effectiveness,
    security posture improvement or verified control closure.</p>
   <p><Link href={`/organizations/${slug}/actions/work`}>
    Open individual work history and coordination</Link></p>
  </section>
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Trend filters</h2>
   <label htmlFor="trend-window">Reporting period</label>
   <select id="trend-window" value={filter.days}
    onChange={event=>update("days",Number(event.target.value) as Filter["days"])}>
    {[7,14,30,60,90].map(n=><option key={n} value={n}>Last {n} days</option>)}
   </select>
   <label htmlFor="trend-scope">Scope</label>
   <select id="trend-scope" value={filter.scope}
    onChange={event=>update("scope",event.target.value as Filter["scope"])}>
    <option value="MINE">Currently assigned to me</option>
    <option value="TEAM">All organization work</option>
   </select>
   <label htmlFor="trend-metric">Event classification</label>
   <select id="trend-metric" value={filter.metric}
    onChange={event=>update("metric",event.target.value as Metric)}>
    <option value="ALL">All recorded event types</option>
    {(["CREATED","COMPLETED","REOPENED","OWNERSHIP","DEADLINE","PRIORITY"] as const)
     .map(key=><option key={key} value={key}>{names[key]}</option>)}
   </select>
   <label><input type="checkbox" checked={filter.includeComments}
    onChange={event=>update("includeComments",event.target.checked)}/>
    Include work comments</label>
   <label><input type="checkbox" checked={filter.includeChecklist}
    onChange={event=>update("includeChecklist",event.target.checked)}/>
    Include checklist activity</label>
   <button type="submit" disabled={loading}>{loading?"Loading…":"Refresh trend analysis"}</button>
  </form>
  {result?<div>
   <section className="panel">
    <h2>Operational change summary</h2>
    <p>{result.from} through {result.to} ·
     {result.coverage.workCount} work records ·
     {result.summary.totalEvents} classified event records.</p>
    <div className="remediation-list">
     <article className="remediation-card"><h3>New tasks</h3><p>{result.summary.created}</p></article>
     <article className="remediation-card"><h3>Marked complete</h3><p>{result.summary.completed}</p></article>
     <article className="remediation-card"><h3>Reopened</h3><p>{result.summary.reopened}</p></article>
     <article className="remediation-card"><h3>Owner changes</h3><p>{result.summary.ownership}</p></article>
     <article className="remediation-card"><h3>Deadline changes</h3><p>{result.summary.deadline}</p></article>
     <article className="remediation-card"><h3>Priority changes</h3><p>{result.summary.priority}</p></article>
     <article className="remediation-card"><h3>Other or unknown</h3>
      <p>{result.summary.other+result.summary.unknown}</p></article>
    </div>
    <p>{result.summary.affectedWork} distinct work items ·
     {result.summary.actors} identifiable actors.</p>
    <p>Current work inventory: {result.summary.openNow} active ·
     {result.summary.doneNow} marked complete ·
     {result.summary.overdueNow} overdue ·
     {result.summary.unassignedNow} unassigned.</p>
    <p className="score-caption">{result.coverage.note}</p>
    <p className="score-caption">{result.disclaimer}</p>
    <button type="button" onClick={download}>Export classified events (CSV)</button>
   </section>
   <section className="panel">
    <h2>Daily activity</h2>
    <p>Select one day to inspect the matching recorded changes. Bar lengths
     represent event volume in the selected window, not security progress.</p>
    <div className="remediation-list">
     {result.days.map(day=><button key={day.date} type="button"
      className="remediation-card" aria-pressed={selectedDay===day.date}
      onClick={()=>{setSelectedDay(current=>current===day.date?null:day.date);setVisible(20);}}>
      <strong>{day.date}</strong> · {day.total} events
      <div style={{height:8,width:`${Math.max(1,day.total/peak*100)}%`,
       background:"currentColor",opacity:0.55}}/>
      <span>{day.completed} completed · {day.reopened} reopened ·
       {day.deadline} deadlines</span>
     </button>)}
    </div>
   </section>
   <section className="panel">
    <h2>{selectedDay?`Recorded changes on ${selectedDay}`:"Recent recorded changes"}</h2>
    <p>{rows.length} events in this view. Classification based on available
     event kind and snapshots.</p>
    <button type="button" onClick={()=>setShowDetails(current=>!current)}>
     {showDetails?"Hide before/after values":"Show before/after values"}
    </button>
    <div className="remediation-list">
     {rows.slice(0,visible).map(item=><article className="remediation-card" key={item.id}>
      <h3>{item.label}</h3>
      <p>Work ID: {item.workItemId} · {item.occurredAt.slice(0,19)} UTC</p>
      <p>Actor: {item.actorUserId??"Unavailable"} ·
       Classification: {item.confidence.toLowerCase()}</p>
      {showDetails?<p>Before: {item.from??"Not recorded"} ·
       After: {item.to??"Not recorded"}</p>:null}
      <p>Event details are historical work metadata, not signed attestations.</p>
     </article>)}
    </div>
    {!rows.length?<p>No events match this view.</p>:null}
    {visible<rows.length?<button type="button"
     onClick={()=>setVisible(current=>current+20)}>Show 20 more events</button>:null}
   </section>
  </div>:null}
 </div>;
}
