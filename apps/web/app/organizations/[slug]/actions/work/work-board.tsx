"use client";

import { useCallback,useEffect,useState,type FormEvent } from "react";
import Link from "next/link";
import WorkChecklist from "./work-checklist";

type Status="TODO"|"IN_PROGRESS"|"BLOCKED"|"DONE"|"CANCELLED";
type Priority="LOW"|"NORMAL"|"HIGH"|"URGENT";
type Assignee={role:string;user:{id:string;name:string;email:string}};
type Candidate={id:string;title:string;status:string;finding:{title:string;severity:string}};
type Item={
  id:string;remediationId:string;title:string;description:string;status:Status;priority:Priority;
  assigneeUserId:string|null;dueAt:string|null;revision:number;
  updatedAt:string;createdAt:string;completedAt:string|null;dueState:string;
  remediation:{title:string;status:string;mode:string};
  finding:{title:string;severity:string;status:string};
  assignee:{id:string;name:string;email:string}|null;
};
type Event={
  id:string;kind:string;occurredAt:string;comment:string|null;
  actor:{name:string;email:string}|null;
  before:unknown;after:unknown;
};
type Detail=Item&{events:Event[];historyTruncated:boolean;totalEvents:number};
type Result={rows:Item[];total:number;pages:number;page:number;pageSize:number};
const STATUSES:Status[]=["TODO","IN_PROGRESS","BLOCKED","DONE","CANCELLED"];
const PRIORITIES:Priority[]=["LOW","NORMAL","HIGH","URGENT"];
const humanStatus:Record<Status,string>={
  TODO:"To do",IN_PROGRESS:"In progress",BLOCKED:"Blocked",DONE:"Work completed",CANCELLED:"Cancelled"
};
const humanPriority:Record<Priority,string>={LOW:"Low",NORMAL:"Normal",HIGH:"High",URGENT:"Urgent"};
function formatDate(value:string|null){
  if(!value)return "No date";
  const date=new Date(value);
  return Number.isNaN(date.getTime())?"Unknown date":date.toISOString().slice(0,10);
}
async function requestJson<T>(url:string,options?:RequestInit):Promise<T>{
  const response=await fetch(url,{...options,cache:"no-store",headers:{
    "Content-Type":"application/json",...options?.headers
  }});
  const body:unknown=await response.json();
  if(!response.ok){
    const error=body&&typeof body==="object"&&"error" in body
      ?String((body as {error:unknown}).error):`Request failed (${response.status}).`;
    throw new Error(error);
  }
  return body as T;
}
type Props={slug:string;canManage:boolean;canComment:boolean;currentUserId:string};
export default function WorkBoard({slug,canManage,canComment,currentUserId}:Props){
  const base=`/api/organizations/${encodeURIComponent(slug)}/actions/work`;
  const [items,setItems]=useState<Result|null>(null);
  const [assignees,setAssignees]=useState<Assignee[]>([]);
  const [candidates,setCandidates]=useState<Candidate[]>([]);
  const [selected,setSelected]=useState<Detail|null>(null);
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [loading,setLoading]=useState(false);
  const [saving,setSaving]=useState(false);
  const [status,setStatus]=useState("ALL");
  const [priority,setPriority]=useState("ALL");
  const [due,setDue]=useState("ALL");
  const [search,setSearch]=useState("");
  const [assignee,setAssignee]=useState("ALL");
  const [page,setPage]=useState(1);
  const [newRemediation,setNewRemediation]=useState("");
  const [newTitle,setNewTitle]=useState("");
  const [newDescription,setNewDescription]=useState("");
  const [newStatus,setNewStatus]=useState<Status>("TODO");
  const [newPriority,setNewPriority]=useState<Priority>("NORMAL");
  const [newAssignee,setNewAssignee]=useState("");
  const [newDue,setNewDue]=useState("");
  const [editTitle,setEditTitle]=useState("");
  const [editDescription,setEditDescription]=useState("");
  const [editStatus,setEditStatus]=useState<Status>("TODO");
  const [editPriority,setEditPriority]=useState<Priority>("NORMAL");
  const [editAssignee,setEditAssignee]=useState("");
  const [editDue,setEditDue]=useState("");
  const [comment,setComment]=useState("");
  const [showCreate,setShowCreate]=useState(false);
  const load=useCallback(async()=>{
    setLoading(true);
    try{
      const q=new URLSearchParams({status,priority,due,search,assignee,page:String(page)});
      const result=await requestJson<Result>(`${base}?${q}`);
      setItems(result);
      setError("");
    }catch(e){setError(e instanceof Error?e.message:"Unable to load work.");}
    finally{setLoading(false);}
  },[base,status,priority,due,search,assignee,page]);
  useEffect(()=>{void load();},[load]);
  useEffect(()=>{
    if(!canManage)return;
    void Promise.all([
      requestJson<{assignees:Assignee[]}>(`${base}?meta=assignees`),
      requestJson<{remediations:Candidate[]}>(`${base}?meta=untracked`)
    ]).then(([people,work])=>{
      setAssignees(people.assignees);
      setCandidates(work.remediations);
    }).catch(e=>setError(e instanceof Error?e.message:"Unable to load choices."));
  },[base,canManage]);
  function fillEdit(item:Detail){
    setSelected(item);
    setEditTitle(item.title);
    setEditDescription(item.description);
    setEditStatus(item.status);
    setEditPriority(item.priority);
    setEditAssignee(item.assigneeUserId??"");
    setEditDue(formatDate(item.dueAt)==="No date"?"":formatDate(item.dueAt));
  }
  async function openItem(id:string){
    try{
      const detail=await requestJson<{item:Detail}>(`${base}/${encodeURIComponent(id)}`);
      fillEdit(detail.item);
      setError("");
    }catch(e){setError(e instanceof Error?e.message:"Unable to open work item.");}
  }
  async function create(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!canManage||saving)return;
    setSaving(true);
    try{
      const result=await requestJson<{item:{id:string}}>(base,{
        method:"POST",body:JSON.stringify({
          remediationId:newRemediation,title:newTitle,description:newDescription,
          status:newStatus,priority:newPriority,assigneeUserId:newAssignee||null,
          dueAt:newDue||null
        })
      });
      setNotice("Work item created. No security control has been verified.");
      setShowCreate(false);
      setNewRemediation("");setNewTitle("");setNewDescription("");
      setCandidates(current=>current.filter(x=>x.id!==newRemediation));
      setPage(1);
      await load();
      await openItem(result.item.id);
    }catch(e){setError(e instanceof Error?e.message:"Unable to create work item.");}
    finally{setSaving(false);}
  }
  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!selected||!canManage||saving)return;
    setSaving(true);
    try{
      await requestJson(`${base}/${encodeURIComponent(selected.id)}`,{
        method:"PATCH",body:JSON.stringify({revision:selected.revision,value:{
          title:editTitle,description:editDescription,status:editStatus,
          priority:editPriority,assigneeUserId:editAssignee||null,dueAt:editDue||null
        }})
      });
      setNotice("Work tracking saved. Completion does not verify the remediation.");
      setError("");
      await Promise.all([load(),openItem(selected.id)]);
    }catch(e){setError(e instanceof Error?e.message:"Unable to save work item.");}
    finally{setSaving(false);}
  }
  async function addComment(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!selected||!canComment||!comment.trim()||saving)return;
    setSaving(true);
    try{
      await requestJson(`${base}/${encodeURIComponent(selected.id)}`,{
        method:"POST",body:JSON.stringify({comment})
      });
      setComment("");
      setNotice("Comment recorded in the work history.");
      setError("");
      await openItem(selected.id);
    }catch(e){setError(e instanceof Error?e.message:"Unable to record comment.");}
    finally{setSaving(false);}
  }
  return <div>
    <section className="panel">
      <h2>Operational work tracking</h2>
      <p>Track assignment, deadlines and human work. These records are not scanner observations, verification evidence or finding closure.</p>
      <p>Signed in member: {currentUserId}</p>
      {canManage?<button type="button" onClick={()=>setShowCreate(x=>!x)}>
        {showCreate?"Close creation form":"Create work item"}
      </button>:<p>Read-only work management. Ask an organization owner or admin to update assignments.</p>}
    </section>
    {error?<p role="alert" className="auth-error">{error}</p>:null}
    {notice?<p role="status">{notice}</p>:null}
    {showCreate&&canManage?<form className="panel remediation-actions" onSubmit={event=>void create(event)}>
      <h2>New work item</h2>
      <label htmlFor="work-remediation">Remediation to coordinate</label>
      <select id="work-remediation" required value={newRemediation} onChange={event=>{
        const id=event.target.value;setNewRemediation(id);
        const candidate=candidates.find(x=>x.id===id);
        if(candidate)setNewTitle(candidate.title);
      }}>
        <option value="">Select a remediation</option>
        {candidates.map(x=><option value={x.id} key={x.id}>{x.title} — {x.finding.severity}</option>)}
      </select>
      <label htmlFor="work-title">Task title</label>
      <input id="work-title" required minLength={3} maxLength={160} value={newTitle}
        onChange={event=>setNewTitle(event.target.value)}/>
      <label htmlFor="work-description">What needs doing</label>
      <textarea id="work-description" maxLength={4000} value={newDescription}
        onChange={event=>setNewDescription(event.target.value)}/>
      <label htmlFor="work-status">Work state</label>
      <select id="work-status" value={newStatus} onChange={event=>setNewStatus(event.target.value as Status)}>
        {STATUSES.map(x=><option value={x} key={x}>{humanStatus[x]}</option>)}
      </select>
      <label htmlFor="work-priority">Coordination priority</label>
      <select id="work-priority" value={newPriority} onChange={event=>setNewPriority(event.target.value as Priority)}>
        {PRIORITIES.map(x=><option value={x} key={x}>{humanPriority[x]}</option>)}
      </select>
      <label htmlFor="work-owner">Assigned teammate</label>
      <select id="work-owner" value={newAssignee} onChange={event=>setNewAssignee(event.target.value)}>
        <option value="">Unassigned</option>
        {assignees.map(x=><option value={x.user.id} key={x.user.id}>{x.user.name} ({x.role})</option>)}
      </select>
      <label htmlFor="work-due">Target date</label>
      <input id="work-due" type="date" value={newDue} onChange={event=>setNewDue(event.target.value)}/>
      <button type="submit" disabled={saving||!newRemediation}>{saving?"Saving…":"Create and record history"}</button>
      <p>One work item per remediation. Creating a work item does not execute a change.</p>
    </form>:null}
    <form className="panel remediation-actions" onSubmit={event=>{event.preventDefault();setPage(1);void load();}}>
      <h2>Find and prioritize work</h2>
      <label htmlFor="work-search">Search</label>
      <input id="work-search" maxLength={120} value={search} onChange={event=>{setPage(1);setSearch(event.target.value);}}/>
      <label htmlFor="filter-state">Status</label>
      <select id="filter-state" value={status} onChange={event=>{setPage(1);setStatus(event.target.value);}}>
        <option value="ALL">All statuses</option>
        {STATUSES.map(x=><option key={x} value={x}>{humanStatus[x]}</option>)}
      </select>
      <label htmlFor="filter-priority">Priority</label>
      <select id="filter-priority" value={priority} onChange={event=>{setPage(1);setPriority(event.target.value);}}>
        <option value="ALL">All priorities</option>
        {PRIORITIES.map(x=><option value={x} key={x}>{humanPriority[x]}</option>)}
      </select>
      <label htmlFor="filter-due">Deadline</label>
      <select id="filter-due" value={due} onChange={event=>{setPage(1);setDue(event.target.value);}}>
        <option value="ALL">Any deadline</option>
        <option value="OVERDUE">Overdue</option>
        <option value="NEXT_7_DAYS">Due within seven days</option>
        <option value="NO_DATE">No deadline</option>
      </select>
      <label htmlFor="filter-assignee">Owner</label>
      <select id="filter-assignee" value={assignee} onChange={event=>{setPage(1);setAssignee(event.target.value);}}>
        <option value="ALL">Everyone</option>
        <option value="UNASSIGNED">Unassigned</option>
        <option value={currentUserId}>Assigned to me</option>
        {assignees.filter(x=>x.user.id!==currentUserId).map(x=>
          <option value={x.user.id} key={x.user.id}>{x.user.name}</option>)}
      </select>
    </form>
    <section className="panel" aria-live="polite">
      <h2>Matching work</h2>
      <p><a href={`${base}/export?${new URLSearchParams({status,priority,due,search,assignee})}`}>Download matching work (CSV, up to 1,000 records)</a></p>
      <p>{loading?"Loading…":`${items?.total??0} work items`}</p>
      {items?.rows.length===0?<p>No work items match these filters.</p>:null}
      <div className="remediation-list">{items?.rows.map(item=>
        <article className="remediation-card" key={item.id}>
          <h3>{item.title}</h3>
          <p>{humanPriority[item.priority]} · {humanStatus[item.status]} · {item.dueState}</p>
          <p>Assigned: {item.assignee?.name??"Nobody"} · Target: {formatDate(item.dueAt)}</p>
          <p>Finding: {item.finding.title} ({item.finding.severity}, {item.finding.status})</p>
          <p>Remediation: {item.remediation.title} ({item.remediation.status})</p>
          <button type="button" onClick={()=>void openItem(item.id)}>Open work and history</button>
        </article>)}</div>
      <nav aria-label="Work pages">
        <button type="button" disabled={page<=1} onClick={()=>setPage(x=>x-1)}>Previous</button>
        <span> Page {page} of {items?.pages??1} </span>
        <button type="button" disabled={!items||page>=items.pages} onClick={()=>setPage(x=>x+1)}>Next</button>
      </nav>
    </section>
    {selected?<section className="panel">
      <h2>Work item: {selected.title}</h2>
      <button type="button" onClick={()=>setSelected(null)}>Close detail</button>
      <p>Revision {selected.revision} · Updated {formatDate(selected.updatedAt)}</p>
      <p>Finding: {selected.finding.title} · {selected.finding.status}</p>
      <p>Remediation state: {selected.remediation.status}</p>
      <p><Link href={`/organizations/${slug}/actions/${selected.remediationId}`}>Go to verification and action details</Link></p>
      {canManage?<form className="remediation-actions" onSubmit={event=>void save(event)}>
        <label htmlFor="edit-work-title">Title</label>
        <input id="edit-work-title" value={editTitle} minLength={3} maxLength={160} onChange={event=>setEditTitle(event.target.value)}/>
        <label htmlFor="edit-work-description">Instructions</label>
        <textarea id="edit-work-description" maxLength={4000} value={editDescription} onChange={event=>setEditDescription(event.target.value)}/>
        <label htmlFor="edit-work-status">Work status</label>
        <select id="edit-work-status" value={editStatus} onChange={event=>setEditStatus(event.target.value as Status)}>
          {STATUSES.map(x=><option value={x} key={x}>{humanStatus[x]}</option>)}
        </select>
        <label htmlFor="edit-work-priority">Priority</label>
        <select id="edit-work-priority" value={editPriority} onChange={event=>setEditPriority(event.target.value as Priority)}>
          {PRIORITIES.map(x=><option value={x} key={x}>{humanPriority[x]}</option>)}
        </select>
        <label htmlFor="edit-work-owner">Assignee</label>
        <select id="edit-work-owner" value={editAssignee} onChange={event=>setEditAssignee(event.target.value)}>
          <option value="">Unassigned</option>
          {assignees.map(x=><option value={x.user.id} key={x.user.id}>{x.user.name}</option>)}
        </select>
        <label htmlFor="edit-work-due">Deadline</label>
        <input id="edit-work-due" type="date" value={editDue} onChange={event=>setEditDue(event.target.value)}/>
        <button type="submit" disabled={saving}>{saving?"Saving…":"Save and record change"}</button>
      </form>:null}
      {canComment?<form className="remediation-actions" onSubmit={event=>void addComment(event)}>
        <label htmlFor="work-comment">Progress note</label>
        <textarea id="work-comment" required maxLength={2000} value={comment} onChange={event=>setComment(event.target.value)}
          placeholder="Record what happened, references and handoff details. This is not verified evidence."/>
        <button type="submit" disabled={saving||!comment.trim()}>Record note</button>
      </form>:null}
      <WorkChecklist slug={slug} workId={selected.id}/>
      <h3>Work history</h3>
      <p>{selected.totalEvents} recorded events. {selected.historyTruncated?"Only the latest 100 are displayed.":""}</p>
      <ol>{selected.events.map(event=><li key={event.id}>
        <strong>{event.kind}</strong> — {formatDate(event.occurredAt)} — {event.actor?.name??"Former member"}
        {event.comment?<p>{event.comment}</p>:null}
        {event.kind!=="COMMENTED"?<details><summary>Recorded change snapshot</summary>
          <pre style={{whiteSpace:"pre-wrap",overflowWrap:"anywhere"}}>{JSON.stringify({before:event.before,after:event.after},null,2)}</pre>
        </details>:null}
      </li>)}</ol>
    </section>:null}
  </div>;
}
