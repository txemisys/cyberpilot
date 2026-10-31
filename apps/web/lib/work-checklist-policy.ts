/**
 * A checklist is a human coordination record, never a security verification.
 * Entries can be acknowledged without touching remediation.status or finding.status.
 */
export type ChecklistRole="OWNER"|"ADMIN"|"MEMBER"|"AUDITOR";
export type ChecklistEntryInput={title:string;description:string};
export type ChecklistEntryPatch={title?:string;description?:string};
export type ChecklistOperation=
 | {kind:"add";workItemId:string;entry:ChecklistEntryInput}
 | {kind:"edit";workItemId:string;entryId:string;entry:ChecklistEntryPatch}
 | {kind:"toggle";workItemId:string;entryId:string;completed:boolean}
 | {kind:"remove";workItemId:string;entryId:string}
 | {kind:"reorder";workItemId:string;entryIds:string[]};
export type ChecklistReadModel={
 id:string;workItemId:string;position:number;title:string;description:string;
 completedAt:Date|null;completedByUserId:string|null;createdAt:Date;updatedAt:Date;
};
export class ChecklistError extends Error {
 constructor(public readonly code:"INVALID"|"FORBIDDEN"|"NOT_FOUND"|"CONFLICT"|"CAPACITY",message:string){
  super(message);this.name="ChecklistError";
 }
}
const ID=/^[a-zA-Z0-9_-]{5,100}$/;
function record(value:unknown):Record<string,unknown>{
 if(!value||typeof value!=="object"||Array.isArray(value))
  throw new ChecklistError("INVALID","Checklist payload must be an object.");
 return value as Record<string,unknown>;
}
function exactKeys(value:Record<string,unknown>,allowed:readonly string[]):void{
 for(const key of Object.keys(value))
  if(!allowed.includes(key))throw new ChecklistError("INVALID",`Unsupported field: ${key}`);
}
export function checklistId(value:unknown):string{
 if(typeof value!=="string"||!ID.test(value))
  throw new ChecklistError("INVALID","Invalid work or checklist identifier.");
 return value;
}
export function checklistTitle(value:unknown):string{
 if(typeof value!=="string")throw new ChecklistError("INVALID","Title must be text.");
 const title=value.trim();
 if(title.length<3||title.length>180||/[\u0000-\u001f\u007f]/.test(title))
  throw new ChecklistError("INVALID","Title must contain 3–180 printable characters.");
 return title;
}
export function checklistDescription(value:unknown):string{
 if(typeof value!=="string"||value.length>3000||/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value))
  throw new ChecklistError("INVALID","Description must be text up to 3000 characters.");
 return value.trim();
}
export function parseChecklistEntry(value:unknown):ChecklistEntryInput{
 const data=record(value);
 exactKeys(data,["title","description"]);
 return {
  title:checklistTitle(data.title),
  description:data.description===undefined?"":checklistDescription(data.description)
 };
}
export function parseChecklistPatch(value:unknown):ChecklistEntryPatch{
 const data=record(value);
 exactKeys(data,["title","description"]);
 const patch:ChecklistEntryPatch={};
 if("title" in data)patch.title=checklistTitle(data.title);
 if("description" in data)patch.description=checklistDescription(data.description);
 if(!Object.keys(patch).length)throw new ChecklistError("INVALID","Empty checklist update.");
 return patch;
}
export function parseChecklistOperation(value:unknown):ChecklistOperation{
 const data=record(value);
 const workItemId=checklistId(data.workItemId);
 switch(data.kind){
  case "add":
   exactKeys(data,["kind","workItemId","entry"]);
   return {kind:"add",workItemId,entry:parseChecklistEntry(data.entry)};
  case "edit":
   exactKeys(data,["kind","workItemId","entryId","entry"]);
   return {kind:"edit",workItemId,entryId:checklistId(data.entryId),entry:parseChecklistPatch(data.entry)};
  case "toggle":
   exactKeys(data,["kind","workItemId","entryId","completed"]);
   if(typeof data.completed!=="boolean")
    throw new ChecklistError("INVALID","Completed must be a boolean.");
   return {kind:"toggle",workItemId,entryId:checklistId(data.entryId),completed:data.completed};
  case "remove":
   exactKeys(data,["kind","workItemId","entryId"]);
   return {kind:"remove",workItemId,entryId:checklistId(data.entryId)};
  case "reorder":
   exactKeys(data,["kind","workItemId","entryIds"]);
   if(!Array.isArray(data.entryIds)||data.entryIds.length>100)
    throw new ChecklistError("INVALID","Expected at most 100 checklist identifiers.");
   const entryIds=data.entryIds.map(checklistId);
   if(new Set(entryIds).size!==entryIds.length)
    throw new ChecklistError("INVALID","Checklist order must not contain duplicates.");
   return {kind:"reorder",workItemId,entryIds};
  default:throw new ChecklistError("INVALID","Unsupported checklist operation.");
 }
}
export function canStructureChecklist(role:ChecklistRole):boolean{
 return role==="OWNER"||role==="ADMIN";
}
export function canAcknowledgeChecklist(role:ChecklistRole,assigneeUserId:string|null,actorUserId:string):boolean{
 return canStructureChecklist(role)||(role==="MEMBER"&&assigneeUserId===actorUserId);
}
export function checklistPermissions(
 role:ChecklistRole,assigneeUserId:string|null,actorUserId:string,operation:ChecklistOperation["kind"]
):void{
 if(operation==="toggle"){
  if(!canAcknowledgeChecklist(role,assigneeUserId,actorUserId))
   throw new ChecklistError("FORBIDDEN","Only the assignee or a manager may acknowledge checklist work.");
  return;
 }
 if(!canStructureChecklist(role))
  throw new ChecklistError("FORBIDDEN","Only organization managers can change checklist structure.");
}
export function validateChecklistReorder(existingIds:readonly string[],nextIds:readonly string[]):void{
 if(existingIds.length!==nextIds.length)
  throw new ChecklistError("CONFLICT","Checklist changed while reordering.");
 const original=new Set(existingIds);
 if(new Set(nextIds).size!==nextIds.length||nextIds.some(id=>!original.has(id)))
  throw new ChecklistError("CONFLICT","Checklist order does not contain exactly the current entries.");
}
export type ChecklistProgress={
 total:number;completed:number;remaining:number;percent:number;
 hasOutstanding:boolean;allAcknowledged:boolean;
};
export function checklistProgress(entries:readonly Pick<ChecklistReadModel,"completedAt">[]):ChecklistProgress{
 let completed=0;
 for(const entry of entries)if(entry.completedAt!==null)completed++;
 const total=entries.length;
 return {
  total,completed,remaining:total-completed,
  percent:total===0?0:Math.round(completed/total*100),
  hasOutstanding:total>completed,
  allAcknowledged:total>0&&completed===total
 };
}
export function checklistNextPosition(positions:readonly number[]):number{
 if(positions.length>=100)throw new ChecklistError("CAPACITY","A work item supports at most 100 checklist entries.");
 const highest=positions.reduce((acc,value)=>Math.max(acc,value),-1);
 if(highest>=2147483646)throw new ChecklistError("CAPACITY","Checklist position limit reached.");
 return highest+1;
}
export function summarizeChecklistActivity(events:readonly {
 kind:string;actorUserId:string|null;occurredAt:Date;
}[],now:Date){
 const since=new Date(now.getTime()-7*24*3600000);
 const recent=events.filter(event=>event.occurredAt>=since&&event.occurredAt<=now);
 const byActor=new Map<string,number>();
 for(const event of recent){
  const key=event.actorUserId??"FORMER_MEMBER";
  byActor.set(key,(byActor.get(key)??0)+1);
 }
 return {recent:recent.length,byActor:[...byActor].map(([actorUserId,count])=>({actorUserId,count}))};
}
export function describeChecklistAction(operation:ChecklistOperation):string{
 switch(operation.kind){
  case "add":return "Added a coordination checklist entry";
  case "edit":return "Updated checklist instructions";
  case "toggle":return operation.completed?"Acknowledged checklist work":"Reopened checklist work";
  case "remove":return "Removed a checklist entry";
  case "reorder":return "Reordered checklist entries";
 }
}
