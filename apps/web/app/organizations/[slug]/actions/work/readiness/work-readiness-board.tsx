"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
import Link from "next/link";
type Level="READY_FOR_HUMAN_REVIEW"|"REQUIRES_ATTENTION"|"BLOCKED"|"CLOSED_REVIEW";
type Issue="NO_OWNER"|"NO_CHECKLIST"|"INCOMPLETE_CHECKLIST"|"NO_EVIDENCE"|
 "PENDING_HANDOFF"|"BLOCKED"|"OVERDUE"|"UNCONFIRMED_FINDING"|"CLOSED_WITH_GAPS";
type Filter={
 scope:"MINE"|"TEAM"|"UNASSIGNED";includeClosed:boolean;
 requireEvidence:boolean;requireChecklist:boolean;onlyExceptions:boolean;search:string;
};
type Decision={
 id:string;title:string;revision:number;status:string;priority:string;
 assigneeUserId:string|null;assigneeName:string|null;
 findingId:string;findingTitle:string;findingStatus:string;findingSeverity:string;
 remediationId:string;remediationTitle:string;remediationStatus:string;
 level:Level;issues:Issue[];totalChecklist:number;completedChecklist:number;
 remainingChecklist:number;activeEvidenceLinks:number;pendingHandoffs:number;
 overdueDays:number|null;dateDue:string|null;completedAt:string|null;
 updatedAt:string;recommendation:string;
};
type Summary={
 total:number;ready:number;attention:number;blocked:number;closedReview:number;
 withoutOwner:number;withoutEvidence:number;withoutChecklist:number;
 incompleteChecklist:number;pendingHandoffs:number;overdue:number;
};
type Model={
 generatedAt:string;summary:Summary;rows:Decision[];totalRows:number;
 coverage:{complete:boolean;limit:number;message:string};disclaimer:string;
};
const initial:Filter={
 scope:"MINE",includeClosed:false,requireEvidence:true,
 requireChecklist:true,onlyExceptions:false,search:"",
};
const names:Record<Level,string>={
 READY_FOR_HUMAN_REVIEW:"Operational review possible",
 REQUIRES_ATTENTION:"Supporting work required",
 BLOCKED:"Dependency or handoff unresolved",
 CLOSED_REVIEW:"Closed work record: review context",
};
const labels:Record<Issue,string>={
 NO_OWNER:"No responsible member",NO_CHECKLIST:"No recorded checklist",
 INCOMPLETE_CHECKLIST:"Checklist steps remain open",
 NO_EVIDENCE:"No active evidence reference",PENDING_HANDOFF:"Handoff awaiting a decision",
 BLOCKED:"Work marked blocked",OVERDUE:"Past target date",
 UNCONFIRMED_FINDING:"Related finding is not confirmed resolved",
 CLOSED_WITH_GAPS:"Closed work has supporting-record gaps",
};
async function request(url:string):Promise<Model>{
 const response=await fetch(url,{cache:"no-store"});
 const parsed:unknown=await response.json();
 if(!response.ok){
  if(parsed&&typeof parsed==="object"&&"error" in parsed)
   throw new Error(String(parsed.error));
  throw new Error(`Request failed (${response.status}).`);
 }
 return parsed as Model;
}
export default function WorkReadinessBoard({slug,canManage}:{
 slug:string;canManage:boolean;
}){
 const [filter,setFilter]=useState<Filter>(initial);
 const [result,setResult]=useState<Model|null>(null);
 const [error,setError]=useState("");
 const [loading,setLoading]=useState(false);
 const [revision,setRevision]=useState(0);
 const [expanded,setExpanded]=useState<Record<string,boolean>>({});
 const [onlyLevel,setOnlyLevel]=useState<Level|"ALL">("ALL");
 const [onlyIssue,setOnlyIssue]=useState<Issue|"ALL">("ALL");
 const api=`/api/organizations/${encodeURIComponent(slug)}/actions/work/readiness`;
 const query=new URLSearchParams({
  ...filter,includeClosed:String(filter.includeClosed),
  requireEvidence:String(filter.requireEvidence),
  requireChecklist:String(filter.requireChecklist),
  onlyExceptions:String(filter.onlyExceptions),
 });
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const model=await request(`${api}?${query}`);
   setResult(model);setError("");setExpanded({});
  }catch(cause){
   setError(cause instanceof Error?cause.message:"Unable to load readiness.");
  }finally{setLoading(false);}
 // Query is a stable serialization of the filters.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[api,query.toString(),revision]);
 useEffect(()=>{void load();},[load]);
 function update<K extends keyof Filter>(field:K,value:Filter[K]){
  setFilter(current=>({...current,[field]:value}));
  setOnlyLevel("ALL");setOnlyIssue("ALL");
 }
 function submit(event:FormEvent<HTMLFormElement>){
  event.preventDefault();setRevision(current=>current+1);
 }
 const visible=result?.rows.filter(row=>
  (onlyLevel==="ALL"||row.level===onlyLevel)&&
  (onlyIssue==="ALL"||row.issues.includes(onlyIssue)))??[];
 return <div>
  <section className="panel">
   <h2>Work closure preparation</h2>
   <p>Inspect real checklist steps, active evidence references, responsibility
    handoffs, ownership and deadlines before requesting operational review.</p>
   <p>This screen never marks a task complete or a finding resolved. An evidence
    link is only a reference; it is not independent validation of that evidence.</p>
   <p><Link href={`/organizations/${slug}/actions/work`}>
    Manage work items, checklists and linked evidence</Link></p>
  </section>
  {error?<p className="auth-error" role="alert">{error}</p>:null}
  <form className="panel remediation-actions" onSubmit={submit}>
   <h2>Review criteria</h2>
   <label htmlFor="readiness-scope">Scope</label>
   <select id="readiness-scope" value={filter.scope}
    onChange={event=>update("scope",event.target.value as Filter["scope"])}>
    <option value="MINE">My assigned work</option>
    <option value="TEAM">All organization work</option>
    <option value="UNASSIGNED">Work without an owner</option>
   </select>
   <label htmlFor="readiness-search">Search work and findings</label>
   <input id="readiness-search" type="search" maxLength={120}
    value={filter.search} onChange={event=>update("search",event.target.value)}/>
   <label><input type="checkbox" checked={filter.requireChecklist}
    onChange={event=>update("requireChecklist",event.target.checked)}/>
    Flag incomplete or missing checklists</label>
   <label><input type="checkbox" checked={filter.requireEvidence}
    onChange={event=>update("requireEvidence",event.target.checked)}/>
    Flag missing evidence references</label>
   <label><input type="checkbox" checked={filter.includeClosed}
    onChange={event=>update("includeClosed",event.target.checked)}/>
    Include completed and cancelled work</label>
   <label><input type="checkbox" checked={filter.onlyExceptions}
    onChange={event=>update("onlyExceptions",event.target.checked)}/>
    Show tasks needing operational attention</label>
   <button type="submit" disabled={loading}>{loading?"Loading…":"Refresh readiness"}</button>
  </form>
  {result?<div>
   <section className="panel">
    <h2>Complete matching inventory</h2>
    <p>{result.summary.total} tracked tasks · {result.summary.ready} ready
     for human operational review · {result.summary.attention} needing work ·
     {result.summary.blocked} blocked · {result.summary.closedReview} closed.</p>
    <div className="remediation-list">
     <article className="remediation-card">
      <h3>Checklist gaps</h3>
      <p>{result.summary.withoutChecklist} missing ·
       {result.summary.incompleteChecklist} incomplete</p>
     </article>
     <article className="remediation-card">
      <h3>Missing evidence references</h3><p>{result.summary.withoutEvidence}</p>
     </article>
     <article className="remediation-card">
      <h3>Pending handoffs</h3><p>{result.summary.pendingHandoffs}</p>
     </article>
     <article className="remediation-card">
      <h3>Without owner</h3><p>{result.summary.withoutOwner}</p>
     </article>
     <article className="remediation-card">
      <h3>Past deadline</h3><p>{result.summary.overdue}</p>
     </article>
    </div>
    <p>{result.coverage.message}</p>
    <p className="score-caption">{result.disclaimer}</p>
    <p>{canManage?"You may update operational records on the main work board.":
     "Review access does not grant work modification privileges."}</p>
   </section>
   <section className="panel">
    <h2>Review queue</h2>
    <div className="remediation-actions">
     <label htmlFor="readiness-level">Level</label>
     <select id="readiness-level" value={onlyLevel}
      onChange={event=>setOnlyLevel(event.target.value as Level|"ALL")}>
      <option value="ALL">All</option>
      {(Object.keys(names) as Level[]).map(key=>
       <option key={key} value={key}>{names[key]}</option>)}
     </select>
     <label htmlFor="readiness-issue">Operational issue</label>
     <select id="readiness-issue" value={onlyIssue}
      onChange={event=>setOnlyIssue(event.target.value as Issue|"ALL")}>
      <option value="ALL">All</option>
      {(Object.keys(labels) as Issue[]).map(key=>
       <option key={key} value={key}>{labels[key]}</option>)}
     </select>
    </div>
    <p>{visible.length} visible of {result.totalRows} review entries.</p>
    {!visible.length?<p>No tasks match the selected review criteria.</p>:null}
    <div className="remediation-list">{visible.map(row=>
     <article className="remediation-card" key={row.id}>
      <h3>{row.title}</h3>
      <p><strong>{names[row.level]}</strong> · {row.status} · {row.priority}</p>
      <p>Responsible: {row.assigneeName??"Unassigned"} ·
       Target: {row.dateDue?.slice(0,10)??"Not scheduled"}</p>
      <p>Checklist: {row.completedChecklist}/{row.totalChecklist} ·
       Active evidence links: {row.activeEvidenceLinks} ·
       Pending handoffs: {row.pendingHandoffs}</p>
      <p>Related finding: {row.findingTitle} ({row.findingSeverity},
       {row.findingStatus})</p>
      <p><strong>Next step:</strong> {row.recommendation}</p>
      <button type="button" aria-expanded={Boolean(expanded[row.id])}
       onClick={()=>setExpanded(current=>({...current,[row.id]:!current[row.id]}))}>
       {expanded[row.id]?"Hide details":"Inspect supporting-record gaps"}
      </button>
      {expanded[row.id]?<div>
       <p>Revision {row.revision} · Last modified {row.updatedAt.slice(0,10)}
        {row.overdueDays!==null?` · ${row.overdueDays} days overdue`:""}</p>
       {row.issues.length?<ul>{row.issues.map(issue=>
        <li key={issue}>{labels[issue]}</li>)}</ul>:<p>No recorded operational gaps.</p>}
       <p>Remediation: {row.remediationTitle} ({row.remediationStatus})</p>
       <p>Completed work timestamp: {row.completedAt?.slice(0,10)??"Not completed"}.</p>
       <p>Checklist and evidence link counts do not attest to evidence validity.</p>
      </div>:null}
      <p><Link href={`/organizations/${slug}/actions/work`}>
       Open tracking to address this task</Link></p>
     </article>)}</div>
   </section>
  </div>:null}
 </div>;
}
