import { db } from "@cyberpilot/database";
import type { Prisma } from "@cyberpilot/database";
import {
 ChecklistError,checklistPermissions,checklistProgress,
 checklistNextPosition,parseChecklistOperation,validateChecklistReorder,
 describeChecklistAction,type ChecklistOperation,type ChecklistRole
} from "./work-checklist-policy";

export type ChecklistContext={organizationId:string;userId:string;role:ChecklistRole};
const entrySelect={
 id:true,organizationId:true,workItemId:true,position:true,
 title:true,description:true,completedAt:true,completedByUserId:true,
 createdAt:true,updatedAt:true,
 completedBy:{select:{name:true,email:true}}
} as const;
export async function readChecklist(context:ChecklistContext,workItemId:string){
 const work=await db.remediationWorkItem.findFirst({
  where:{id:workItemId,organizationId:context.organizationId},
  select:{
   id:true,title:true,status:true,assigneeUserId:true,
   remediationId:true,findingId:true,updatedAt:true
  }
 });
 if(!work)throw new ChecklistError("NOT_FOUND","Work item not found in this organization.");
 const entries=await db.workChecklistEntry.findMany({
  where:{organizationId:context.organizationId,workItemId},
  select:entrySelect,orderBy:[{position:"asc"},{id:"asc"}],take:101
 });
 if(entries.length>100)
  throw new ChecklistError("CAPACITY","Checklist capacity exceeded; contact support.");
 return {
  work,entries,progress:checklistProgress(entries),
  canStructure:context.role==="OWNER"||context.role==="ADMIN",
  canAcknowledge:context.role==="OWNER"||context.role==="ADMIN"||
    (context.role==="MEMBER"&&work.assigneeUserId===context.userId),
  disclaimer:"Checklist acknowledgments are human work records, not verified security evidence."
 };
}
async function workInScope(tx:Prisma.TransactionClient,context:ChecklistContext,workItemId:string){
 const work=await tx.remediationWorkItem.findFirst({
  where:{id:workItemId,organizationId:context.organizationId},
  select:{id:true,assigneeUserId:true,status:true,revision:true}
 });
 if(!work)throw new ChecklistError("NOT_FOUND","Work item not found.");
 return work;
}
async function entryInScope(
 tx:Prisma.TransactionClient,context:ChecklistContext,workItemId:string,entryId:string
){
 const row=await tx.workChecklistEntry.findFirst({
  where:{id:entryId,workItemId,organizationId:context.organizationId}
 });
 if(!row)throw new ChecklistError("NOT_FOUND","Checklist entry not found.");
 return row;
}
async function recordEvent(
 tx:Prisma.TransactionClient,context:ChecklistContext,workItemId:string,
 operation:ChecklistOperation,before:unknown,after:unknown
){
 // Reuses the immutable work-event stream, with machine-readable change snapshots.
 await tx.remediationWorkEvent.create({
  data:{
   organizationId:context.organizationId,workItemId,actorUserId:context.userId,
   kind:"UPDATED",comment:describeChecklistAction(operation),
   before:before===null?undefined:before as Prisma.InputJsonValue,
   after:after===null?undefined:after as Prisma.InputJsonValue
  }
 });
}
function auditSnapshot(entry:{
 id:string;position:number;title:string;description:string;
 completedAt:Date|null;completedByUserId:string|null
}){
 return {
  checklistEntryId:entry.id,
  position:entry.position,title:entry.title,description:entry.description,
  completedAt:entry.completedAt?.toISOString()??null,
  completedByUserId:entry.completedByUserId
 };
}
async function addEntry(
 tx:Prisma.TransactionClient,context:ChecklistContext,operation:Extract<ChecklistOperation,{kind:"add"}>
){
 const existing=await tx.workChecklistEntry.findMany({
  where:{organizationId:context.organizationId,workItemId:operation.workItemId},
  select:{position:true},orderBy:{position:"asc"},take:101
 });
 const position=checklistNextPosition(existing.map(x=>x.position));
 const entry=await tx.workChecklistEntry.create({
  data:{
   organizationId:context.organizationId,workItemId:operation.workItemId,
   position,title:operation.entry.title,description:operation.entry.description
  }
 });
 await recordEvent(tx,context,operation.workItemId,operation,null,auditSnapshot(entry));
 return entry;
}
async function editEntry(
 tx:Prisma.TransactionClient,context:ChecklistContext,operation:Extract<ChecklistOperation,{kind:"edit"}>
){
 const previous=await entryInScope(tx,context,operation.workItemId,operation.entryId);
 const next=await tx.workChecklistEntry.update({
  where:{id:previous.id},data:operation.entry
 });
 await recordEvent(tx,context,operation.workItemId,operation,
  auditSnapshot(previous),auditSnapshot(next));
 return next;
}
async function toggleEntry(
 tx:Prisma.TransactionClient,context:ChecklistContext,operation:Extract<ChecklistOperation,{kind:"toggle"}>
){
 const previous=await entryInScope(tx,context,operation.workItemId,operation.entryId);
 // Repeating an already-applied intent is idempotent and does not insert a fake event.
 if((previous.completedAt!==null)===operation.completed)return previous;
 const next=await tx.workChecklistEntry.update({
  where:{id:previous.id},
  data:{
   completedAt:operation.completed?new Date():null,
   completedByUserId:operation.completed?context.userId:null
  }
 });
 await recordEvent(tx,context,operation.workItemId,operation,
  auditSnapshot(previous),auditSnapshot(next));
 return next;
}
async function removeEntry(
 tx:Prisma.TransactionClient,context:ChecklistContext,operation:Extract<ChecklistOperation,{kind:"remove"}>
){
 const previous=await entryInScope(tx,context,operation.workItemId,operation.entryId);
 await tx.workChecklistEntry.delete({where:{id:previous.id}});
 await recordEvent(tx,context,operation.workItemId,operation,auditSnapshot(previous),null);
 return {deletedId:previous.id};
}
async function reorderEntries(
 tx:Prisma.TransactionClient,context:ChecklistContext,operation:Extract<ChecklistOperation,{kind:"reorder"}>
){
 const entries=await tx.workChecklistEntry.findMany({
  where:{organizationId:context.organizationId,workItemId:operation.workItemId},
  orderBy:[{position:"asc"},{id:"asc"}],take:101
 });
 validateChecklistReorder(entries.map(x=>x.id),operation.entryIds);
 const before=entries.map(x=>({id:x.id,position:x.position}));
 if(before.every((x,i)=>x.id===operation.entryIds[i]))return {changed:false};
 // First move positions into a non-colliding temporary band; the unique
 // workItemId+position constraint is then preserved during the second pass.
 for(let i=0;i<entries.length;i++){
  const current=entries[i];
  if(!current)continue;
  await tx.workChecklistEntry.update({where:{id:current.id},data:{position:1000+i}});
 }
 for(let i=0;i<operation.entryIds.length;i++){
  const id=operation.entryIds[i];
  if(!id)continue;
  await tx.workChecklistEntry.update({where:{id},data:{position:i}});
 }
 await recordEvent(tx,context,operation.workItemId,operation,before,
  operation.entryIds.map((id,position)=>({id,position})));
 return {changed:true};
}
export async function mutateChecklist(context:ChecklistContext,input:unknown){
 const operation=parseChecklistOperation(input);
 return db.$transaction(async tx=>{
  const work=await workInScope(tx,context,operation.workItemId);
  checklistPermissions(context.role,work.assigneeUserId,context.userId,operation.kind);
  switch(operation.kind){
   case "add":return addEntry(tx,context,operation);
   case "edit":return editEntry(tx,context,operation);
   case "toggle":return toggleEntry(tx,context,operation);
   case "remove":return removeEntry(tx,context,operation);
   case "reorder":return reorderEntries(tx,context,operation);
  }
 },{isolationLevel:"Serializable"});
}
export async function checklistOverview(context:ChecklistContext,workItemIds:readonly string[]){
 if(workItemIds.length>100)throw new ChecklistError("CAPACITY","Too many work items requested.");
 const unique=[...new Set(workItemIds)];
 const rows=await db.workChecklistEntry.findMany({
  where:{organizationId:context.organizationId,workItemId:{in:unique}},
  select:{workItemId:true,completedAt:true}
 });
 const byWork=new Map<string,{total:number;completed:number}>();
 for(const id of unique)byWork.set(id,{total:0,completed:0});
 for(const row of rows){
  const count=byWork.get(row.workItemId);
  if(!count)continue;
  count.total++;
  if(row.completedAt!==null)count.completed++;
 }
 return [...byWork].map(([workItemId,value])=>({
  workItemId,...value,
  percentage:value.total===0?0:Math.round(100*value.completed/value.total),
  allAcknowledged:value.total>0&&value.completed===value.total
 }));
}
