import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {
 EvidenceLinkError,authorizeEvidenceLink,parseEvidenceCommand,parseEvidenceId,
 parseEvidenceSearch,assessLinkedEvidence,summarizeLinks,enforceLinkCapacity,
 evidenceCandidateSort,type LinkRole
} from "./work-evidence-policy";

export type EvidenceLinkContext={organizationId:string;userId:string;role:LinkRole};
const evidenceSelect={
 id:true,organizationId:true,source:true,domain:true,controlId:true,scope:true,
 state:true,observedAt:true,createdAt:true,updatedAt:true
} as const;
const linkSelect={
 id:true,organizationId:true,workItemId:true,evidenceId:true,reason:true,
 linkedAt:true,unlinkedAt:true,linkedByUserId:true,unlinkedByUserId:true,
 evidence:{select:evidenceSelect},
 linkedBy:{select:{name:true,email:true}},
 unlinkedBy:{select:{name:true,email:true}}
} as const;
async function lookupWork(tx:Prisma.TransactionClient,scope:EvidenceLinkContext,workId:string){
 const item=await tx.remediationWorkItem.findFirst({
  where:{id:workId,organizationId:scope.organizationId},
  select:{
   id:true,title:true,status:true,assigneeUserId:true,
   finding:{select:{id:true,title:true,ruleId:true,key:true,status:true}}
  }
 });
 if(!item)throw new EvidenceLinkError("NOT_FOUND","Work item not found.");
 return item;
}
function eventSnapshot(link:{
 id:string;evidenceId:string;reason:string;linkedAt:Date;unlinkedAt:Date|null
}){
 return {
  linkId:link.id,evidenceId:link.evidenceId,reason:link.reason,
  linkedAt:link.linkedAt.toISOString(),unlinkedAt:link.unlinkedAt?.toISOString()??null
 };
}
async function logLink(
 tx:Prisma.TransactionClient,scope:EvidenceLinkContext,workItemId:string,
 action:string,before:unknown,after:unknown
){
 await tx.remediationWorkEvent.create({
  data:{
   organizationId:scope.organizationId,workItemId,actorUserId:scope.userId,
   kind:"UPDATED",comment:action,
   ...(before===null?{}:{before:before as Prisma.InputJsonValue}),
   ...(after===null?{}:{after:after as Prisma.InputJsonValue})
  }
 });
}
export async function listWorkEvidence(scope:EvidenceLinkContext,workId:string,now=new Date()){
 const work=await db.remediationWorkItem.findFirst({
  where:{id:workId,organizationId:scope.organizationId},
  select:{
   id:true,title:true,assigneeUserId:true,
   finding:{select:{title:true,ruleId:true,key:true,status:true}}
  }
 });
 if(!work)throw new EvidenceLinkError("NOT_FOUND","Work item not found.");
 const links=await db.workEvidenceLink.findMany({
  where:{organizationId:scope.organizationId,workItemId:workId},
  select:linkSelect,orderBy:[{linkedAt:"desc"},{id:"asc"}],take:101
 });
 if(links.length>100)
  throw new EvidenceLinkError("CAPACITY","Too many historical references for this work item.");
 const result=links.map(link=>({
  ...link,assessment:assessLinkedEvidence(link.evidence,work.finding,now)
 }));
 return {
  work,links:result,
  summary:summarizeLinks(links,work.finding,now),
  canEdit:scope.role==="OWNER"||scope.role==="ADMIN"||
   (scope.role==="MEMBER"&&work.assigneeUserId===scope.userId),
  disclaimer:"An evidence reference is a review aid, not evidence of completed verification."
 };
}
export async function findEvidenceCandidates(
 scope:EvidenceLinkContext,workId:string,search:unknown
){
 const work=await db.remediationWorkItem.findFirst({
  where:{id:workId,organizationId:scope.organizationId},
  select:{finding:{select:{ruleId:true,key:true,status:true}}}
 });
 if(!work)throw new EvidenceLinkError("NOT_FOUND","Work item not found.");
 const term=parseEvidenceSearch(search);
 const rows=await db.securityEvidence.findMany({
  where:{
   organizationId:scope.organizationId,
   ...(term?{OR:[
    {controlId:{contains:term,mode:"insensitive"}},
    {source:{contains:term,mode:"insensitive"}},
    {domain:{contains:term,mode:"insensitive"}},
    {scope:{contains:term,mode:"insensitive"}}
   ]}:{OR:[{controlId:work.finding.ruleId},{controlId:work.finding.key}]})
  },
  select:evidenceSelect,orderBy:[{observedAt:"desc"},{id:"asc"}],take:100
 });
 return {
  candidates:evidenceCandidateSort(rows,work.finding).map(row=>({
   ...row,assessment:assessLinkedEvidence(row,work.finding)
  })),
  truncated:rows.length===100,
  disclaimer:"Matching a control ID is only a candidate relationship; inspect scope and provenance."
 };
}
export async function mutateWorkEvidence(scope:EvidenceLinkContext,workId:string,input:unknown){
 const command=parseEvidenceCommand(input);
 const evidenceId=parseEvidenceId(command.evidenceId);
 return db.$transaction(async tx=>{
  const work=await lookupWork(tx,scope,workId);
  authorizeEvidenceLink(scope.role,work.assigneeUserId,scope.userId);
  const existing=await tx.workEvidenceLink.findFirst({
   where:{organizationId:scope.organizationId,workItemId:workId,evidenceId}
  });
  if(command.kind==="detach"){
   if(!existing)throw new EvidenceLinkError("NOT_FOUND","Evidence reference not found.");
   if(existing.unlinkedAt)return {changed:false,link:existing};
   const next=await tx.workEvidenceLink.update({
    where:{id:existing.id},data:{unlinkedAt:new Date(),unlinkedByUserId:scope.userId}
   });
   await logLink(tx,scope,workId,"Detached evidence reference",
    eventSnapshot(existing),eventSnapshot(next));
   return {changed:true,link:next};
  }
  const evidence=await tx.securityEvidence.findFirst({
   where:{id:evidenceId,organizationId:scope.organizationId},select:evidenceSelect
  });
  if(!evidence)
   throw new EvidenceLinkError("NOT_FOUND","Evidence record not found in this organization.");
  const activeCount=await tx.workEvidenceLink.count({
   where:{organizationId:scope.organizationId,workItemId:workId,unlinkedAt:null}
  });
  if(existing&&!existing.unlinkedAt)
   throw new EvidenceLinkError("CONFLICT","Evidence is already linked.");
  enforceLinkCapacity(activeCount);
  if(command.kind==="attach"&&existing)
   throw new EvidenceLinkError("CONFLICT","Previously detached link must be restored explicitly.");
  if(command.kind==="restore"&&!existing)
   throw new EvidenceLinkError("NOT_FOUND","No prior reference exists to restore.");
  if(command.kind==="attach"){
   const link=await tx.workEvidenceLink.create({
    data:{
     organizationId:scope.organizationId,workItemId:workId,evidenceId,
     reason:command.reason,linkedByUserId:scope.userId
    }
   });
   await logLink(tx,scope,workId,"Linked stored evidence record",null,eventSnapshot(link));
   return {changed:true,link,assessment:assessLinkedEvidence(evidence,work.finding)};
  }
  if(!existing)throw new EvidenceLinkError("NOT_FOUND","Reference not found.");
  const next=await tx.workEvidenceLink.update({
   where:{id:existing.id},
   data:{
    reason:command.reason,linkedAt:new Date(),linkedByUserId:scope.userId,
    unlinkedAt:null,unlinkedByUserId:null
   }
  });
  await logLink(tx,scope,workId,"Restored evidence reference",
   eventSnapshot(existing),eventSnapshot(next));
  return {changed:true,link:next,assessment:assessLinkedEvidence(evidence,work.finding)};
 },{isolationLevel:"Serializable"});
}
export async function evidenceLinkSummaryForWork(
 scope:EvidenceLinkContext,workIds:readonly string[]
){
 const ids=[...new Set(workIds)];
 if(ids.length>100)throw new EvidenceLinkError("CAPACITY","Too many work items.");
 const links=await db.workEvidenceLink.findMany({
  where:{organizationId:scope.organizationId,workItemId:{in:ids},unlinkedAt:null},
  select:{workItemId:true,evidence:{select:{state:true,observedAt:true}}}
 });
 const count=new Map(ids.map(id=>[id,{total:0,observed:0,notObserved:0}]));
 for(const link of links){
  const item=count.get(link.workItemId);
  if(!item)continue;
  item.total++;
  if(link.evidence.state==="OBSERVED")item.observed++;
  else item.notObserved++;
 }
 return [...count].map(([workItemId,summary])=>({workItemId,...summary,
  note:"Linked observations require independent review before verification."
 }));
}
