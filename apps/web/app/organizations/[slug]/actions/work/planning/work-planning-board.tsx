"use client";

import {useState,type FormEvent} from "react";
import Link from "next/link";
type MemberLoad={
 userId:string;name:string;role:string;capacityPoints:number;
 existingPoints:number;plannedPoints:number;availablePoints:number;
 available:boolean;existingItems:number;plannedItems:number;
 overdueItems:number;urgentItems:number;utilizationPercent:number|null;
};
type Allocation={
 workId:string;title:string;revision:number;priority:string;
 dueAt:string|null;findingSeverity:string;fromUserId:string|null;
 proposedUserId:string|null;points:number;
 action:"ASSIGN"|"REASSIGN"|"KEEP"|"UNPLACED";reason:string;
};
type Scenario={
 generatedAt:string;cutoff:string;parameters:Options;
 totalOpenWork:number;considered:number;proposedMoves:number;
 unplaced:number;excluded:number;
 members:MemberLoad[];allocations:Allocation[];notes:string[];
 coverage:{totalFetched:number;truncated:boolean;reason:string};
};
type Options={
 horizonDays:7|14|30|60|90;
 scope:"UNASSIGNED"|"ALL_OPEN";
 capacityPoints:number;
 settings:{userId:string;capacityPoints:number;available:boolean}[];
 includeBlocked:boolean;maxMoves:number;preserveOwners:boolean;
};
type Preview={
 ready:boolean;executable:number;total:number;
 decisions:{id:string;field:string;current:string|null;
 proposed:string|null;outcome:string;message:string}[];
};
type Applied={changed:number;items:{id:string;revision:number}[];note:string};
const initial:Options={
 horizonDays:30,scope:"UNASSIGNED",capacityPoints:20,settings:[],
 includeBlocked:false,maxMoves:50,preserveOwners:true,
};
async function post<T>(url:string,body:unknown):Promise<T>{
 const response=await fetch(url,{
  method:"POST",cache:"no-store",headers:{"Content-Type":"application/json"},
  body:JSON.stringify(body),
 });
 const parsed:unknown=await response.json();
 if(!response.ok){
  if(parsed&&typeof parsed==="object"&&"error" in parsed)
   throw new Error(String(parsed.error));
  throw new Error(`Request failed: ${response.status}`);
 }
 return parsed as T;
}
function percent(value:number|null){return value===null?"No capacity":`${value}%`;}
function date(value:string|null){
 if(!value)return "No target date";
 const parsed=new Date(value);
 return Number.isNaN(parsed.getTime())?"Unrecognized date":parsed.toISOString().slice(0,10);
}
export default function WorkPlanningBoard({slug}:{slug:string}){
 const api=`/api/organizations/${encodeURIComponent(slug)}/actions/work`;
 const [options,setOptions]=useState<Options>(initial);
 const [scenario,setScenario]=useState<Scenario|null>(null);
 const [preview,setPreview]=useState<Preview|null>(null);
 const [reason,setReason]=useState("");
 const [error,setError]=useState("");
 const [notice,setNotice]=useState("");
 const [busy,setBusy]=useState(false);
 const [chosen,setChosen]=useState<string[]>([]);
 const moves=scenario?.allocations.filter(row=>
  (row.action==="ASSIGN"||row.action==="REASSIGN")&&row.proposedUserId)??[];
 const selected=moves.filter(row=>chosen.includes(row.workId));
 function resetScenario(){
  setScenario(null);setPreview(null);setChosen([]);setNotice("");
 }
 function setOption<K extends keyof Options>(key:K,value:Options[K]){
  setOptions(current=>({...current,[key]:value}));
  resetScenario();
 }
 function memberSetting(userId:string,field:"available"|"capacityPoints",value:boolean|number){
  setOptions(current=>{
   const existing=current.settings.find(row=>row.userId===userId);
   const others=current.settings.filter(row=>row.userId!==userId);
   const currentMember=scenario?.members.find(row=>row.userId===userId);
   const base=existing??{
    userId,capacityPoints:currentMember?.capacityPoints??current.capacityPoints,
    available:currentMember?.available??true,
   };
   return {...current,settings:[...others,{...base,[field]:value}]};
  });
  resetScenario();
 }
 async function calculate(event?:FormEvent<HTMLFormElement>){
  event?.preventDefault();
  if(busy)return;
  setBusy(true);setError("");setNotice("");
  try{
   const result=await post<Scenario>(`${api}/planning`,options);
   setScenario(result);
   setChosen(result.allocations.filter(row=>
    row.action==="ASSIGN"||row.action==="REASSIGN").map(row=>row.workId));
   setPreview(null);
  }catch(cause){setError(cause instanceof Error?cause.message:"Planning failed.");}
  finally{setBusy(false);}
 }
 function batchChanges(){
  return selected.map(row=>({
   id:row.workId,revision:row.revision,
   field:"assigneeUserId" as const,value:row.proposedUserId,
  }));
 }
 async function run(mode:"preview"|"apply"){
  if(busy||!scenario||scenario.coverage.truncated||!selected.length||
     reason.trim().length<10)return;
  setBusy(true);setError("");setNotice("");
  try{
   const payload={mode,reason,changes:batchChanges()};
   if(mode==="preview"){
    const result=await post<Preview>(`${api}/batch`,payload);
    setPreview(result);
    if(!result.ready)setNotice("Resolve revision or membership conflicts before applying.");
   }else{
    if(!preview?.ready)throw new Error("Preview all changes before applying.");
    const result=await post<Applied>(`${api}/batch`,payload);
    setScenario(null);setPreview(null);setChosen([]);setReason("");
    setNotice(`${result.changed} task assignments updated. The security state is unchanged.`);
   }
  }catch(cause){
   setPreview(null);
   setError(cause instanceof Error?cause.message:"Unable to validate assignments.");
  }finally{setBusy(false);}
 }
 function toggle(id:string){
  setChosen(current=>current.includes(id)?
   current.filter(value=>value!==id):[...current,id]);
  setPreview(null);
 }
 function allMoves(){
  setChosen(moves.map(row=>row.workId));setPreview(null);
 }
 function noMoves(){setChosen([]);setPreview(null);}
 function updateReason(value:string){setReason(value);setPreview(null);}
 return <div>
  <section className="panel">
   <h2>Assignment scenario</h2>
   <p>Plan against existing task ownership, severity, priority and due dates.
    Capacity points are a hypothetical budget you choose. They are not
    staff hours, measured productivity or verified capacity.</p>
   <p className="permission-warning">No assignment is changed by calculation.
    Applying changes requires a second revision-checked database operation.
    Completed work does not verify any security control.</p>
   <p><Link href={`/organizations/${slug}/actions/work`}>Open current operational work</Link></p>
  </section>
  {error?<p className="auth-error" role="alert">{error}</p>:null}
  {notice?<p role="status">{notice}</p>:null}
  <form onSubmit={event=>void calculate(event)} className="panel remediation-actions">
   <h2>Scenario parameters</h2>
   <label htmlFor="plan-horizon">Planning horizon</label>
   <select id="plan-horizon" value={options.horizonDays}
    onChange={event=>setOption("horizonDays",Number(event.target.value) as Options["horizonDays"])}>
    {[7,14,30,60,90].map(day=><option key={day} value={day}>{day} days</option>)}
   </select>
   <label htmlFor="plan-scope">Tasks to consider</label>
   <select id="plan-scope" value={options.scope}
    onChange={event=>setOption("scope",event.target.value as Options["scope"])}>
    <option value="UNASSIGNED">Unassigned open tasks only</option>
    <option value="ALL_OPEN">All open tasks within horizon</option>
   </select>
   <label htmlFor="plan-capacity">Default capacity points per person</label>
   <input id="plan-capacity" type="number" min={0} max={1000}
    value={options.capacityPoints}
    onChange={event=>setOption("capacityPoints",Number(event.target.value))}/>
   <label htmlFor="plan-max">Maximum proposed moves</label>
   <input id="plan-max" type="number" min={1} max={50}
    value={options.maxMoves}
    onChange={event=>setOption("maxMoves",Number(event.target.value))}/>
   <label><input type="checkbox" checked={options.includeBlocked}
    onChange={event=>setOption("includeBlocked",event.target.checked)}/>
    Include blocked tasks in the scenario</label>
   <label><input type="checkbox" checked={options.preserveOwners}
    onChange={event=>setOption("preserveOwners",event.target.checked)}/>
    Keep existing owners when considering assigned work</label>
   <button type="submit" disabled={busy}>{busy?"Calculating…":"Calculate scenario"}</button>
  </form>
  {scenario?<section className="panel">
   <h2>Scenario results</h2>
   <p>Calculated {date(scenario.generatedAt)} · horizon ends {date(scenario.cutoff)}.</p>
   <p>{scenario.totalOpenWork} open tasks · {scenario.considered} considered ·
    {scenario.proposedMoves} proposed moves · {scenario.unplaced} unplaced ·
    {scenario.excluded} outside scenario scope.</p>
   <p>{scenario.coverage.reason}</p>
   {scenario.coverage.truncated?<p role="alert" className="auth-error">
    Inventory truncated. Applying proposals is disabled because the allocation
    may be distorted by missing work.</p>:null}
   <h3>Member load and scenario capacity</h3>
   <div className="remediation-list">
    {scenario.members.map(member=><article className="remediation-card" key={member.userId}>
     <h4>{member.name} ({member.role})</h4>
     <p>Current: {member.existingItems} tasks, {member.existingPoints} points.
      Proposed: {member.plannedItems} tasks, {member.plannedPoints} points.</p>
     <p>Capacity: {member.capacityPoints} · Remaining: {member.availablePoints} ·
      Utilization: {percent(member.utilizationPercent)}</p>
     <p>Overdue: {member.overdueItems} · Urgent: {member.urgentItems}</p>
     <label htmlFor={`capacity-${member.userId}`}>Scenario capacity</label>
     <input id={`capacity-${member.userId}`} type="number" min={0} max={1000}
      defaultValue={member.capacityPoints}
      onChange={event=>memberSetting(member.userId,"capacityPoints",Number(event.target.value))}/>
     <label><input type="checkbox" defaultChecked={member.available}
      onChange={event=>memberSetting(member.userId,"available",event.target.checked)}/>
      Available for new allocations</label>
    </article>)}
   </div>
   {options.settings.length?<p>Member settings changed. Recalculate before reviewing proposals.</p>:null}
   <h3>Proposed assignments</h3>
   <p>{moves.length} possible changes. Select which to submit for validation.</p>
   <button type="button" onClick={allMoves}>Select all proposed moves</button>
   <button type="button" onClick={noMoves}>Deselect all</button>
   <div className="remediation-list">
    {scenario.allocations.map(row=><article className="remediation-card" key={row.workId}>
     {row.action==="ASSIGN"||row.action==="REASSIGN"?<label>
      <input type="checkbox" checked={chosen.includes(row.workId)}
       onChange={()=>toggle(row.workId)}/>
      Include proposed reassignment
     </label>:null}
     <h4>{row.title}</h4>
     <p>{row.priority} · {row.findingSeverity} · {row.points} points ·
      {date(row.dueAt)} · {row.action}</p>
     <p>From: {scenario.members.find(member=>member.userId===row.fromUserId)?.name??"Unassigned"}
      {" "}→ To: {scenario.members.find(member=>member.userId===row.proposedUserId)?.name??"Unassigned"}</p>
     <p>{row.reason}</p>
    </article>)}
   </div>
   <h3>Review and apply selected moves</h3>
   <p>{selected.length} selected changes out of {moves.length} proposed.</p>
   <label htmlFor="plan-reason">Auditable business reason</label>
   <textarea id="plan-reason" required minLength={10} maxLength={1000}
    value={reason} onChange={event=>updateReason(event.target.value)}
    placeholder="Explain why these tasks should be reassigned."/>
   <button type="button" disabled={busy||!selected.length||
    reason.trim().length<10||scenario.coverage.truncated}
    onClick={()=>void run("preview")}>Validate selections against current database</button>
   {preview?<div>
    <h4>Database preflight</h4>
    <p>{preview.executable} executable of {preview.total} changes.
     {preview.ready?" All selected changes are valid.":" Some changes are invalid or stale."}</p>
    <ul>{preview.decisions.map(row=><li key={row.id}>
     {row.id}: {row.current??"Unassigned"} → {row.proposed??"Unassigned"}
     {" "}· {row.outcome}: {row.message}
    </li>)}</ul>
    <button type="button" disabled={busy||!preview.ready||!preview.executable}
     onClick={()=>void run("apply")}>Apply reviewed assignments atomically</button>
   </div>:null}
   <h3>Interpretation limits</h3>
   <ul>{scenario.notes.map(note=><li key={note}>{note}</li>)}</ul>
  </section>:null}
 </div>;
}
