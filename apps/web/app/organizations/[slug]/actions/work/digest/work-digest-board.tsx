"use client";
import {useEffect,useState,useCallback,type FormEvent} from "react";
import Link from "next/link";
type Scope="MINE"|"TEAM"|"UNASSIGNED";
type Config={scope:Scope;days:7|14|30|60|90;includeClosed:boolean;maxItems:number};
type Work={id:string;title:string;status:string;priority:string;owner:string;
 dueAt:string|null;reasons:string[];weight:number;daysOverdue:number|null;
 daysIdle:number;checklistDone:number;checklistTotal:number;
 activeEvidence:number;pendingHandoffs:number};
type Summary={total:number;open:number;closed:number;overdue:number;blocked:number;
 unassigned:number;urgent:number;stale:number;missingEvidence:number;
 incompleteChecklist:number;pendingHandoffs:number;dueWithinWindow:number};
type Digest={generatedAt:string;cutoff:string;summary:Summary;priorities:Work[];
 followUps:{kind:string;count:number;recommendation:string}[];
 coverage:{complete:boolean;inventory:number;limit:number;excludedFromPreview:number};
 disclaimer:string};
const initial:Config={scope:"MINE",days:14,includeClosed:false,maxItems:30};
const names:Record<string,string>={
 OVERDUE:"Past target date",DUE_WITHIN_WINDOW:"Deadline approaching",
 BLOCKED:"Blocked operational task",UNASSIGNED:"No assigned member",
 URGENT:"Urgent task",STALE:"No update in 14 days",
 MISSING_EVIDENCE_LINK:"No active supporting evidence reference",
 CHECKLIST_GAP:"Checklist missing or incomplete",
 PENDING_HANDOFF:"Assignment handoff awaits a decision",
};
async function fetchDigest(url:string):Promise<Digest>{
 const response=await fetch(url,{cache:"no-store"});
 const value:unknown=await response.json();
 if(!response.ok){
  if(value&&typeof value==="object"&&"error" in value)throw new Error(String(value.error));
  throw new Error(`Digest failed (${response.status}).`);
 }
 return value as Digest;
}
export default function WorkDigestBoard({slug}:{slug:string}){
 const [config,setConfig]=useState<Config>(initial);
 const [digest,setDigest]=useState<Digest|null>(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [revision,setRevision]=useState(0);
 const [selected,setSelected]=useState<string>("ALL");
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const params=new URLSearchParams({...config,
  days:String(config.days),includeClosed:String(config.includeClosed),
  maxItems:String(config.maxItems)});
 const url=`/api/organizations/${encodeURIComponent(slug)}/actions/work/digest?${params}`;
 const refresh=useCallback(async()=>{
  setLoading(true);
  try{const result=await fetchDigest(url);setDigest(result);setError("");setExpanded({});}
  catch(cause){setError(cause instanceof Error?cause.message:"Unknown digest error.");}
  finally{setLoading(false);}
 },[url,revision]);
 useEffect(()=>{void refresh();},[refresh]);
 function update<K extends keyof Config>(key:K,value:Config[K]){
  setConfig(current=>({...current,[key]:value}));setSelected("ALL");
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRevision(current=>current+1);
 }
 const visible=digest?.priorities.filter(item=>selected==="ALL"||
  item.reasons.includes(selected))??[];
 return <div>
  <section className="panel">
   <h2>Actionable operational digest</h2>
   <p>A complete, bounded snapshot of recorded remediation coordination:
    blockers, overdue tasks, missing owners, incomplete checklists,
    evidence references and pending handoffs.</p>
   <p>This report is generated on demand and does not deliver
    scheduled emails or independently verify any security control.</p>
   <p><Link href={`/organizations/${slug}/actions/work`}>
    Open work management to record actual changes</Link></p>
  </section>
  {error?<p className="auth-error" role="alert">{error}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Report scope</h2>
   <label htmlFor="digest-scope">Work ownership</label>
   <select id="digest-scope" value={config.scope}
    onChange={event=>update("scope",event.target.value as Scope)}>
    <option value="MINE">My assigned tasks</option>
    <option value="TEAM">Organization work</option>
    <option value="UNASSIGNED">Unassigned work</option>
   </select>
   <label htmlFor="digest-days">Upcoming work window</label>
   <select id="digest-days" value={config.days}
    onChange={event=>update("days",Number(event.target.value) as Config["days"])}>
    {[7,14,30,60,90].map(value=><option value={value} key={value}>{value} days</option>)}
   </select>
   <label htmlFor="digest-limit">Maximum priority tasks shown</label>
   <select id="digest-limit" value={config.maxItems}
    onChange={event=>update("maxItems",Number(event.target.value))}>
    {[10,20,30,50,100].map(value=><option key={value} value={value}>{value}</option>)}
   </select>
   <label><input type="checkbox" checked={config.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include completed and cancelled tasks</label>
   <button type="submit" disabled={loading}>
    {loading?"Preparing snapshot…":"Refresh operational digest"}
   </button>
  </form>
  {digest?<div>
   <section className="panel">
    <h2>At-a-glance coordination status</h2>
    <p>{digest.summary.total} matching tasks ·
     {digest.summary.open} active · {digest.summary.closed} closed.</p>
    <p>Snapshot: {digest.generatedAt.slice(0,19)} UTC ·
     upcoming window ends {digest.cutoff.slice(0,10)}.</p>
    <div className="remediation-list">
     {([
      ["overdue","Overdue"],["blocked","Blocked"],
      ["unassigned","Unassigned"],["urgent","Urgent"],
      ["stale","Inactive"],["missingEvidence","Evidence link gaps"],
      ["incompleteChecklist","Checklist gaps"],["pendingHandoffs","Handoffs pending"],
      ["dueWithinWindow","Upcoming due dates"],
     ] as const).map(([key,label])=><article className="remediation-card" key={key}>
      <h3>{label}</h3><p>{digest.summary[key]}</p>
     </article>)}
    </div>
    <p>{digest.coverage.inventory} task records considered;
     {digest.coverage.excludedFromPreview} omitted from the priority preview
     because of your display limit, not from the summary.</p>
    <p className="score-caption">{digest.disclaimer}</p>
   </section>
   <section className="panel">
    <h2>Recommended follow-up categories</h2>
    {!digest.followUps.length?<p>No follow-up category has current recorded issues.</p>:null}
    <div className="remediation-list">{digest.followUps.map(item=>
     <article className="remediation-card" key={item.kind}>
      <h3>{names[item.kind]??item.kind}</h3>
      <p>{item.count} matching work items.</p>
      <p>{item.recommendation}</p>
      <button type="button" onClick={()=>setSelected(
       current=>current===item.kind?"ALL":item.kind)}>
       {selected===item.kind?"Show all":"Show affected priority tasks"}
      </button>
     </article>)}</div>
   </section>
   <section className="panel">
    <h2>Highest-attention recorded work</h2>
    <label htmlFor="digest-filter">Filter displayed priority tasks</label>
    <select id="digest-filter" value={selected} onChange={event=>setSelected(event.target.value)}>
     <option value="ALL">All reasons</option>
     {Object.keys(names).map(key=><option key={key} value={key}>{names[key]}</option>)}
    </select>
    <p>{visible.length} shown of {digest.priorities.length} priority-preview records.</p>
    {!visible.length?<p>No priority tasks match this reason in the current preview.</p>:null}
    <div className="remediation-list">{visible.map(row=><article className="remediation-card" key={row.id}>
     <h3>{row.title}</h3>
     <p>{row.priority} priority · {row.status} ·
      operational attention index {row.weight}</p>
     <p>Responsible: {row.owner} ·
      target {row.dueAt?.slice(0,10)??"not recorded"}.</p>
     <p>{row.daysIdle} days since latest recorded update ·
      {row.checklistDone}/{row.checklistTotal} checklist steps ·
      {row.activeEvidence} active evidence links ·
      {row.pendingHandoffs} pending handoffs.</p>
     <button type="button" aria-expanded={Boolean(expanded[row.id])}
      onClick={()=>setExpanded(current=>({...current,[row.id]:!current[row.id]}))}>
      {expanded[row.id]?"Hide reasons":"Review attention reasons"}
     </button>
     {expanded[row.id]?<ul>{row.reasons.map(reason=><li key={reason}>
      {names[reason]??reason}</li>)}</ul>:null}
     <p><Link href={`/organizations/${slug}/actions/work`}>Open task coordination</Link></p>
    </article>)}</div>
   </section>
  </div>:null}
 </div>;
}
