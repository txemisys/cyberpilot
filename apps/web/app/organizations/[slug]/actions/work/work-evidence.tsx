"use client";
import {useCallback,useEffect,useState,type FormEvent} from "react";
type Assessment={
 state:string;age:string;relationship:string;isObserved:boolean;isExplicitMatch:boolean;
 maySupportReview:boolean;warnings:string[];
};
type Evidence={
 id:string;source:string;domain:string;controlId:string;scope:string;
 state:string;observedAt:string|null;
};
type Link={
 id:string;evidenceId:string;reason:string;linkedAt:string;unlinkedAt:string|null;
 evidence:Evidence;assessment:Assessment;
 linkedBy:{name:string}|null;unlinkedBy:{name:string}|null;
};
type Model={
 work:{id:string;title:string;finding:{title:string;ruleId:string;key:string;status:string}};
 links:Link[];summary:{
  active:number;detached:number;exactMatches:number;recentObservedReferences:number;
  mismatched:number;needsReview:number;disclaimer:string;
 };canEdit:boolean;disclaimer:string;
};
type Candidate=Evidence&{assessment:Assessment};
type CandidateModel={candidates:Candidate[];truncated:boolean;disclaimer:string};
type Command=
 |{kind:"attach";evidenceId:string;reason:string}
 |{kind:"restore";evidenceId:string;reason:string}
 |{kind:"detach";evidenceId:string};
async function getJson<T>(url:string,init?:RequestInit):Promise<T>{
 const response=await fetch(url,{cache:"no-store",...init});
 const result:unknown=await response.json();
 if(!response.ok){
  if(result&&typeof result==="object"&&"error" in result)
   throw new Error(String((result as {error:unknown}).error));
  throw new Error(`Request failed (${response.status})`);
 }
 return result as T;
}
function displayDate(value:string|null){
 if(!value)return "Not recorded";
 const parsed=new Date(value);
 return Number.isNaN(parsed.getTime())?"Invalid timestamp":parsed.toISOString().replace("T"," ").slice(0,19)+" UTC";
}
function AssessmentPanel({assessment}:{assessment:Assessment}){
 return <div>
  <p>Evidence state: <strong>{assessment.state}</strong> · Age: {assessment.age}</p>
  <p>Control relationship: {assessment.relationship}</p>
  {assessment.maySupportReview?
   <p>Recent observed reference for further review; this does not establish successful verification.</p>:null}
  {assessment.warnings.length?<ul>{assessment.warnings.map((warning,i)=><li key={i}>{warning}</li>)}</ul>:null}
 </div>;
}
export default function WorkEvidence({slug,workId}:{slug:string;workId:string}){
 const endpoint=`/api/organizations/${encodeURIComponent(slug)}/actions/work/${encodeURIComponent(workId)}/evidence`;
 const [model,setModel]=useState<Model|null>(null);
 const [candidates,setCandidates]=useState<CandidateModel|null>(null);
 const [search,setSearch]=useState("");
 const [chosen,setChosen]=useState("");
 const [reason,setReason]=useState("");
 const [restoring,setRestoring]=useState<string|null>(null);
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [busy,setBusy]=useState(false);
 const [loading,setLoading]=useState(true);
 const [candidateLoading,setCandidateLoading]=useState(false);
 const [showDetached,setShowDetached]=useState(false);
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const value=await getJson<Model>(endpoint);
   setModel(value);setError("");
  }catch(e){setError(e instanceof Error?e.message:"Unable to read linked evidence.");}
  finally{setLoading(false);}
 },[endpoint]);
 useEffect(()=>{void load();},[load]);
 async function discover(){
  setCandidateLoading(true);
  try{
   const query=new URLSearchParams({view:"candidates",search});
   setCandidates(await getJson<CandidateModel>(`${endpoint}?${query}`));
   setError("");
  }catch(e){setError(e instanceof Error?e.message:"Unable to discover evidence.");}
  finally{setCandidateLoading(false);}
 }
 async function apply(command:Command,description:string){
  if(busy)return false;
  setBusy(true);setError("");setNotice("");
  try{
   await getJson(endpoint,{
    method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(command)
   });
   setNotice(description);
   await load();
   return true;
  }catch(e){
   setError(e instanceof Error?e.message:"Evidence reference operation failed.");
   return false;
  }finally{setBusy(false);}
 }
 async function link(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!chosen||reason.trim().length<8)return;
  const done=await apply({kind:"attach",evidenceId:chosen,reason},
   "Evidence reference recorded; separate verification is still required.");
  if(done){setChosen("");setReason("");await discover();}
 }
 async function restore(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!restoring||reason.trim().length<8)return;
  const done=await apply({kind:"restore",evidenceId:restoring,reason},
   "Evidence reference restored. Its observation has not been revalidated.");
  if(done){setRestoring(null);setReason("");}
 }
 const shown=(model?.links??[]).filter(link=>showDetached||!link.unlinkedAt);
 return <section className="panel" aria-label="Stored evidence references">
  <h2>Evidence references for this work item</h2>
  <p><a href={`${endpoint}/export`}>Export evidence references and review limitations (CSV)</a></p>
  <p>Reference an existing organization observation to support human review. Linking an observation does not perform a scan, verify a remediation, or close a finding.</p>
  {loading?<p role="status">Loading evidence references…</p>:null}
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  {model?<div>
   <p><strong>{model.summary.active}</strong> active references · {model.summary.detached} detached ·
    {model.summary.exactMatches} exact control matches ·
    {model.summary.recentObservedReferences} recently observed references</p>
   <p className="score-caption">{model.summary.disclaimer}</p>
   <p>Finding: {model.work.finding.title} ({model.work.finding.status})</p>
   <p>Rule: {model.work.finding.ruleId} · Finding key: {model.work.finding.key}</p>
   <label><input type="checkbox" checked={showDetached}
    onChange={event=>setShowDetached(event.target.checked)}/> Include detached references</label>
   {shown.length===0?<p>No stored evidence references in this view.</p>:null}
   <ol className="remediation-list">
    {shown.map(link=><li className="remediation-card" key={link.id}>
     <h3>{link.evidence.controlId} · {link.evidence.source}</h3>
     <p>Domain: {link.evidence.domain} · Scope: {link.evidence.scope}</p>
     <p>Observed: {displayDate(link.evidence.observedAt)}</p>
     <AssessmentPanel assessment={link.assessment}/>
     <p>Why linked: {link.reason}</p>
     <p>Linked: {displayDate(link.linkedAt)} · By: {link.linkedBy?.name??"Former member"}</p>
     {link.unlinkedAt?<p>Detached: {displayDate(link.unlinkedAt)} · By: {link.unlinkedBy?.name??"Former member"}</p>:null}
     {model.canEdit&&link.unlinkedAt===null?
      <button type="button" disabled={busy} onClick={()=>void apply({
       kind:"detach",evidenceId:link.evidenceId
      },"Reference detached; previous audit history is retained.")}>Detach reference</button>:null}
     {model.canEdit&&link.unlinkedAt!==null?
      <button type="button" disabled={busy} onClick={()=>{
       setRestoring(link.evidenceId);setReason(link.reason);setChosen("");
      }}>Restore with a new rationale</button>:null}
    </li>)}
   </ol>
   {model.canEdit?<div className="panel">
    <h3>Discover stored evidence</h3>
    <p>Search uses up to 100 records per request. Results are limited to this organization.</p>
    <form className="remediation-actions" onSubmit={event=>{event.preventDefault();void discover();}}>
     <label htmlFor="evidence-search">Control, source, domain or scope</label>
     <input id="evidence-search" maxLength={120} value={search}
      onChange={event=>setSearch(event.target.value)} placeholder="Leave empty to find exact control ID matches"/>
     <button type="submit" disabled={candidateLoading}>
      {candidateLoading?"Searching…":"Find existing observations"}
     </button>
    </form>
    {candidates?<div>
     <p>{candidates.candidates.length} candidates shown. {candidates.truncated?"Results may be truncated; narrow your search.":""}</p>
     <p>{candidates.disclaimer}</p>
     <div className="remediation-list">
      {candidates.candidates.map(item=><article className="remediation-card" key={item.id}>
       <h4>{item.controlId} · {item.source}</h4>
       <p>{item.domain} · {item.scope} · {displayDate(item.observedAt)}</p>
       <AssessmentPanel assessment={item.assessment}/>
       <button type="button" onClick={()=>{setChosen(item.id);setRestoring(null);setReason("");}}>
        Reference this observation
       </button>
      </article>)}
     </div>
    </div>:null}
    {chosen?<form className="remediation-actions" onSubmit={event=>void link(event)}>
     <h3>Reference selected stored observation</h3>
     <p>Evidence ID: {chosen}</p>
     <label htmlFor="evidence-reason">Why is this observation relevant?</label>
     <textarea id="evidence-reason" required minLength={8} maxLength={1500}
      value={reason} onChange={event=>setReason(event.target.value)}/>
     <button type="submit" disabled={busy||reason.trim().length<8}>Record evidence reference</button>
     <button type="button" onClick={()=>setChosen("")}>Cancel</button>
    </form>:null}
    {restoring?<form className="remediation-actions" onSubmit={event=>void restore(event)}>
     <h3>Restore detached reference</h3>
     <p>Evidence ID: {restoring}</p>
     <label htmlFor="restore-reason">Updated rationale</label>
     <textarea id="restore-reason" required minLength={8} maxLength={1500}
      value={reason} onChange={event=>setReason(event.target.value)}/>
     <button type="submit" disabled={busy||reason.trim().length<8}>Restore reference</button>
     <button type="button" onClick={()=>setRestoring(null)}>Cancel</button>
    </form>:null}
   </div>:<p>Read-only evidence references. A manager or assigned teammate can change links.</p>}
  </div>:null}
 </section>;
}
