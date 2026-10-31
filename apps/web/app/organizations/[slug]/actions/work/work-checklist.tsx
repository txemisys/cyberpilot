"use client";

import { useCallback,useEffect,useMemo,useState,type FormEvent } from "react";
type Entry={
 id:string;position:number;title:string;description:string;
 completedAt:string|null;completedByUserId:string|null;
 completedBy:{name:string;email:string}|null;
 createdAt:string;updatedAt:string;
};
type ChecklistResponse={
 work:{id:string;title:string;status:string;assigneeUserId:string|null};
 entries:Entry[];
 progress:{total:number;completed:number;remaining:number;percent:number;allAcknowledged:boolean};
 canStructure:boolean;canAcknowledge:boolean;disclaimer:string;
};
type Operation=
 | {kind:"add";entry:{title:string;description:string}}
 | {kind:"edit";entryId:string;entry:{title:string;description:string}}
 | {kind:"toggle";entryId:string;completed:boolean}
 | {kind:"remove";entryId:string}
 | {kind:"reorder";entryIds:string[]};
function safeError(value:unknown):string{
 return value instanceof Error?value.message:"Checklist request failed.";
}
async function readJson<T>(url:string,options?:RequestInit):Promise<T>{
 const result=await fetch(url,{cache:"no-store",...options});
 const parsed:unknown=await result.json();
 if(!result.ok){
  if(parsed&&typeof parsed==="object"&&"error" in parsed)
   throw new Error(String((parsed as {error:unknown}).error));
  throw new Error(`Request failed: ${result.status}`);
 }
 return parsed as T;
}
function isoDate(value:string|null):string{
 if(!value)return "Not acknowledged";
 const at=new Date(value);
 return Number.isNaN(at.getTime())?"Unknown date":at.toISOString().slice(0,16).replace("T"," ");
}
export default function WorkChecklist({slug,workId}:{slug:string;workId:string}){
 const endpoint=`/api/organizations/${encodeURIComponent(slug)}/actions/work/${encodeURIComponent(workId)}/checklist`;
 const [model,setModel]=useState<ChecklistResponse|null>(null);
 const [busy,setBusy]=useState(false);
 const [loading,setLoading]=useState(true);
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [newTitle,setNewTitle]=useState("");
 const [newDescription,setNewDescription]=useState("");
 const [editId,setEditId]=useState<string|null>(null);
 const [editTitle,setEditTitle]=useState("");
 const [editDescription,setEditDescription]=useState("");
 const [confirmRemove,setConfirmRemove]=useState<string|null>(null);
 const [showCompleted,setShowCompleted]=useState(true);
 const [showDetails,setShowDetails]=useState(false);
 const load=useCallback(async()=>{
  setLoading(true);
  try{
   const result=await readJson<ChecklistResponse>(endpoint);
   setModel(result);setError("");
  }catch(caught){setError(safeError(caught));}
  finally{setLoading(false);}
 },[endpoint]);
 useEffect(()=>{void load();},[load]);
 const sorted=useMemo(()=>model?.entries.slice().sort((a,b)=>a.position-b.position)||[],[model]);
 const shown=useMemo(()=>showCompleted?sorted:sorted.filter(x=>x.completedAt===null),[showCompleted,sorted]);
 const hasOutstanding=model?model.progress.remaining>0:false;
 async function mutate(operation:Operation,success:string){
  if(busy)return;
  setBusy(true);setError("");setNotice("");
  try{
   await readJson(endpoint,{
    method:"POST",headers:{"Content-Type":"application/json"},
    body:JSON.stringify(operation)
   });
   await load();
   setNotice(success);
  }catch(caught){setError(safeError(caught));}
  finally{setBusy(false);}
 }
 async function add(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!newTitle.trim()||busy)return;
  await mutate({kind:"add",entry:{title:newTitle,description:newDescription}},"Checklist entry created.");
  setNewTitle("");setNewDescription("");
 }
 async function save(event:FormEvent<HTMLFormElement>){
  event.preventDefault();
  if(!editId||busy)return;
  await mutate({kind:"edit",entryId:editId,entry:{title:editTitle,description:editDescription}},
   "Checklist instructions updated.");
  setEditId(null);
 }
 function startEdit(entry:Entry){
  setEditId(entry.id);setEditTitle(entry.title);setEditDescription(entry.description);
  setConfirmRemove(null);
 }
 function cancelEdit(){
  setEditId(null);setEditTitle("");setEditDescription("");
 }
 function move(id:string,direction:-1|1){
  const from=sorted.findIndex(x=>x.id===id);
  const to=from+direction;
  if(from<0||to<0||to>=sorted.length)return;
  const ids=sorted.map(x=>x.id);
  const swap=ids[from],other=ids[to];
  if(!swap||!other)return;
  ids[from]=other;ids[to]=swap;
  void mutate({kind:"reorder",entryIds:ids},"Checklist order saved.");
 }
 return <section className="panel" aria-label="Operational work checklist">
  <h2>Coordination checklist</h2>
  <p>Use this list to split a remediation into attributable human steps, without marking security controls verified.</p>
  {loading?<p role="status">Loading checklist…</p>:null}
  {error?<p role="alert" className="auth-error">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  {model?<div>
   <div className="panel">
    <p><strong>{model.progress.completed} of {model.progress.total}</strong> steps acknowledged
     ({model.progress.percent}%).</p>
    <progress value={model.progress.completed} max={Math.max(1,model.progress.total)}
     aria-label="Checklist acknowledgments"/>
    {model.progress.allAcknowledged?
     <p>All coordination steps are acknowledged. Independent verification is still required.</p>:
     hasOutstanding?<p>{model.progress.remaining} human work steps still pending.</p>:
     <p>No checklist steps have been recorded.</p>}
    <p className="score-caption">{model.disclaimer}</p>
   </div>
   <div className="remediation-actions">
    <label htmlFor="show-completed-checklist">
     <input type="checkbox" id="show-completed-checklist" checked={showCompleted}
      onChange={event=>setShowCompleted(event.target.checked)}/> Show acknowledged steps
    </label>
    <button type="button" onClick={()=>setShowDetails(x=>!x)}>
     {showDetails?"Hide instructions":"Show all instructions"}
    </button>
    <button type="button" disabled={busy} onClick={()=>void load()}>Refresh work checklist</button>
   </div>
   {shown.length===0?<p>No steps in this view.</p>:null}
   <ol className="remediation-list">
    {shown.map((entry,index)=><li key={entry.id} className="remediation-card">
     <div className="remediation-heading">
      <div>
       <p className="priority-score">Step {entry.position+1} · {entry.completedAt?"Acknowledged":"Pending"}</p>
       <h3>{entry.title}</h3>
      </div>
      <span className="role-badge">{entry.completedAt?"Recorded":"Not done"}</span>
     </div>
     {showDetails||entry.completedAt===null?<p>{entry.description||"No additional instructions supplied."}</p>:null}
     {entry.completedAt?<p>
      Recorded {isoDate(entry.completedAt)} UTC by {entry.completedBy?.name??"Former organization member"}.
     </p>:null}
     {model.canAcknowledge?<label>
      <input type="checkbox" checked={entry.completedAt!==null} disabled={busy}
       onChange={event=>void mutate({
        kind:"toggle",entryId:entry.id,completed:event.target.checked
       },event.target.checked?"Work acknowledgment recorded.":"Work step reopened.")}/>
      {entry.completedAt?"Acknowledge step as completed":"Record this human work step as completed"}
     </label>:<p>Only the assignee or an organization manager can acknowledge this step.</p>}
     {model.canStructure?<div className="remediation-actions">
      <button type="button" disabled={busy||index===0} onClick={()=>move(entry.id,-1)}>Move up</button>
      <button type="button" disabled={busy||index===shown.length-1||!showCompleted}
       onClick={()=>move(entry.id,1)}>Move down</button>
      <button type="button" disabled={busy} onClick={()=>startEdit(entry)}>Edit step</button>
      {confirmRemove===entry.id?
       <div role="group" aria-label="Confirm checklist deletion">
        <p>This removes the current checklist entry, but the recorded work event remains in the item history.</p>
        <button type="button" disabled={busy} onClick={()=>{
         setConfirmRemove(null);
         void mutate({kind:"remove",entryId:entry.id},"Checklist entry removed.");
        }}>Confirm removal</button>
        <button type="button" onClick={()=>setConfirmRemove(null)}>Cancel</button>
       </div>:
       <button type="button" disabled={busy} onClick={()=>setConfirmRemove(entry.id)}>Remove step</button>}
     </div>:null}
     {model.canStructure&&editId===entry.id?
      <form className="remediation-actions" onSubmit={event=>void save(event)}>
       <label htmlFor={`edit-title-${entry.id}`}>Step title</label>
       <input id={`edit-title-${entry.id}`} required minLength={3} maxLength={180}
        value={editTitle} onChange={event=>setEditTitle(event.target.value)}/>
       <label htmlFor={`edit-details-${entry.id}`}>Instructions</label>
       <textarea id={`edit-details-${entry.id}`} maxLength={3000}
        value={editDescription} onChange={event=>setEditDescription(event.target.value)}/>
       <button type="submit" disabled={busy}>Save updated instructions</button>
       <button type="button" onClick={cancelEdit}>Cancel edit</button>
      </form>:null}
    </li>)}
   </ol>
   {model.canStructure?<form className="remediation-actions" onSubmit={event=>void add(event)}>
    <h3>Add a coordination step</h3>
    <label htmlFor="new-checklist-title">Step title</label>
    <input id="new-checklist-title" required minLength={3} maxLength={180}
     value={newTitle} onChange={event=>setNewTitle(event.target.value)}/>
    <label htmlFor="new-checklist-details">Detailed instructions</label>
    <textarea id="new-checklist-details" maxLength={3000} value={newDescription}
     onChange={event=>setNewDescription(event.target.value)}/>
    <button type="submit" disabled={busy||model.entries.length>=100||newTitle.trim().length<3}>
     Add step and record change
    </button>
    <p>Maximum 100 coordination steps per work item.</p>
   </form>:null}
  </div>:null}
 </section>;
}
