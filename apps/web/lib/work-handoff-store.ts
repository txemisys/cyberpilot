import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {
 HandoffError,parseHandoffCommand,assertHandoffPermission,assertPendingHandoff,
 handoffLabel,handoffSummary,orderHandoffs,type HandoffRole
} from "./work-handoff-policy";
export type HandoffContext={organizationId:string;userId:string;role:HandoffRole};
const select={
 id:true,organizationId:true,workItemId:true,requesterUserId:true,
 recipientUserId:true,decidedByUserId:true,status:true,reason:true,response:true,
 requestedAt:true,decidedAt:true,expiresAt:true,revision:true,
 recipient:{select:{name:true,email:true}},
 requester:{select:{name:true,email:true}},
 decider:{select:{name:true,email:true}},
 workItem:{select:{title:true,status:true,assigneeUserId:true,
  finding:{select:{title:true,status:true,severity:true}}}}
} as const;
async function event(tx:Prisma.TransactionClient,scope:HandoffContext,workItemId:string,
 label:string,before:unknown,after:unknown){
 await tx.remediationWorkEvent.create({data:{
  organizationId:scope.organizationId,workItemId,actorUserId:scope.userId,
  kind:"UPDATED",comment:label,
  ...(before===null?{}:{before:before as Prisma.InputJsonValue}),
  ...(after===null?{}:{after:after as Prisma.InputJsonValue})
 }});
}
function snapshot(handoff:{
 id:string;status:string;recipientUserId:string;requesterUserId:string|null;
 reason:string;response:string|null;revision:number
}){
 return {handoffId:handoff.id,status:handoff.status,
  recipientUserId:handoff.recipientUserId,requesterUserId:handoff.requesterUserId,
  reason:handoff.reason,response:handoff.response,revision:handoff.revision};
}
export async function listHandoffs(
 scope:HandoffContext,filter:"ALL"|"INBOX"|"PENDING"="ALL",now=new Date()
){
 const where:Prisma.WorkHandoffWhereInput={organizationId:scope.organizationId};
 if(filter==="INBOX")where.recipientUserId=scope.userId;
 if(filter==="PENDING")where.status="REQUESTED";
 const [total,rows]=await db.$transaction([
  db.workHandoff.count({where}),
  db.workHandoff.findMany({where,select,
   orderBy:[{requestedAt:"desc"},{id:"desc"}],take:100})
 ],{isolationLevel:"RepeatableRead"});
 return {
  total,limited:total>100,
  rows:orderHandoffs(rows,now).map(x=>({...x,label:handoffLabel(x,now),
   mayDecide:x.status==="REQUESTED"&&x.recipientUserId===scope.userId&&
    scope.role!=="AUDITOR"&&(!x.expiresAt||x.expiresAt>now),
   mayCancel:x.status==="REQUESTED"&&(scope.role==="OWNER"||scope.role==="ADMIN"||
    x.requesterUserId===scope.userId&&scope.role!=="AUDITOR")
  })),
  summary:handoffSummary(rows,now),
  disclaimer:"Acceptance assigns work only; it does not certify a control or close findings."
 };
}
export async function handoffInboxAttention(scope:HandoffContext,now=new Date()){
 const rows=await db.workHandoff.findMany({
  where:{organizationId:scope.organizationId,recipientUserId:scope.userId},
  select:{
   id:true,recipientUserId:true,requesterUserId:true,status:true,
   requestedAt:true,expiresAt:true,
   workItem:{select:{status:true,priority:true,dueAt:true}}
  },orderBy:{requestedAt:"desc"},take:100
 });
 const {prioritizeHandoffAttention,groupHandoffInbox}=await import("./work-handoff-export");
 const prioritized=prioritizeHandoffAttention(rows,now);
 return {
  total:prioritized.length,
  attention:prioritized,
  recipients:groupHandoffInbox(rows,now),
  disclaimer:"These are operational handoff deadlines, not verified security outcomes."
 };
}
export async function createHandoff(scope:HandoffContext,input:unknown){
 const command=parseHandoffCommand({kind:"request",...(input as object)});
 if(command.kind!=="request")throw new HandoffError("INVALID","Invalid request.");
 assertHandoffPermission(scope.role,"request",scope.userId,scope.userId,command.recipientUserId);
 return db.$transaction(async tx=>{
  const work=await tx.remediationWorkItem.findFirst({
   where:{id:command.workItemId,organizationId:scope.organizationId},
   select:{id:true,assigneeUserId:true,status:true}
  });
  if(!work)throw new HandoffError("NOT_FOUND","Work item not found.");
  if(work.status==="CANCELLED")
   throw new HandoffError("CONFLICT","Cancelled work cannot receive a new handoff.");
  if(work.assigneeUserId===command.recipientUserId)
   throw new HandoffError("CONFLICT","Recipient is already the assigned owner.");
  const member=await tx.membership.findFirst({
   where:{organizationId:scope.organizationId,userId:command.recipientUserId},
   select:{userId:true,role:true}
  });
  if(!member||member.role==="AUDITOR")
   throw new HandoffError("INVALID","Recipient must be an active non-auditor organization member.");
  const existing=await tx.workHandoff.findFirst({
   where:{organizationId:scope.organizationId,workItemId:work.id,status:"REQUESTED"},
   select:{id:true}
  });
  if(existing)throw new HandoffError("CONFLICT","A handoff is already awaiting a decision.");
  const request=await tx.workHandoff.create({data:{
   organizationId:scope.organizationId,workItemId:work.id,requesterUserId:scope.userId,
   recipientUserId:command.recipientUserId,reason:command.reason,expiresAt:command.expiresAt
  }});
  await event(tx,scope,work.id,"Requested an assignment handoff",null,snapshot(request));
  return request;
 },{isolationLevel:"Serializable"});
}
export async function decideHandoff(scope:HandoffContext,input:unknown){
 const command=parseHandoffCommand(input);
 if(command.kind!=="decide"&&command.kind!=="cancel")
  throw new HandoffError("INVALID","Expected a handoff decision or cancellation.");
 return db.$transaction(async tx=>{
  const existing=await tx.workHandoff.findFirst({
   where:{id:command.handoffId,organizationId:scope.organizationId}
  });
  if(!existing)throw new HandoffError("NOT_FOUND","Handoff not found.");
  assertHandoffPermission(scope.role,command.kind,scope.userId,
   existing.requesterUserId,existing.recipientUserId);
  assertPendingHandoff(existing,command.revision,new Date(),command.kind==="cancel");
  const work=await tx.remediationWorkItem.findFirst({
   where:{id:existing.workItemId,organizationId:scope.organizationId}
  });
  if(!work)throw new HandoffError("NOT_FOUND","Work item not found.");
  if(work.status==="CANCELLED")
   throw new HandoffError("CONFLICT","Cannot transfer cancelled work.");
  if(command.kind==="decide"&&command.decision==="ACCEPTED"){
   const member=await tx.membership.findFirst({
    where:{organizationId:scope.organizationId,userId:existing.recipientUserId},
    select:{userId:true,role:true}
   });
   if(!member||member.role==="AUDITOR")
    throw new HandoffError("CONFLICT","Recipient no longer has an eligible membership.");
   const updated=await tx.remediationWorkItem.updateMany({
    where:{id:work.id,organizationId:scope.organizationId,revision:work.revision},
    data:{assigneeUserId:existing.recipientUserId,revision:{increment:1}}
   });
   if(updated.count!==1)throw new HandoffError("CONFLICT","Work assignment changed concurrently.");
  }
  const status=command.kind==="cancel"?"CANCELLED":command.decision;
  const updated=await tx.workHandoff.updateMany({
   where:{id:existing.id,organizationId:scope.organizationId,revision:existing.revision,status:"REQUESTED"},
   data:{status,response:command.response,decidedByUserId:scope.userId,
    decidedAt:new Date(),revision:{increment:1}}
  });
  if(updated.count!==1)throw new HandoffError("CONFLICT","Handoff changed concurrently.");
  const next=await tx.workHandoff.findFirstOrThrow({
   where:{id:existing.id,organizationId:scope.organizationId}
  });
  await event(tx,scope,work.id,
   status==="ACCEPTED"?"Accepted assignment handoff":
   status==="DECLINED"?"Declined assignment handoff":"Cancelled assignment handoff",
   snapshot(existing),snapshot(next));
  return next;
 },{isolationLevel:"Serializable"});
}
