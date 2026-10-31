import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {
 HistoryInputError,parseHistoryFilter,historyIdentifier,
 historyOrderWhere,makeHistoryPage,histogramHistory,activityByActor,
 activityDayBuckets,serializeAuditHistory,type HistoryFilter
} from "./work-audit-history";
export type AuditContext={organizationId:string;userId:string;role:string};
const eventSelect={
 id:true,organizationId:true,workItemId:true,kind:true,
 actorUserId:true,comment:true,before:true,after:true,occurredAt:true,
 actor:{select:{name:true,email:true}}
} as const;
async function findScopedWork(scope:AuditContext,workId:string){
 const id=historyIdentifier(workId);
 const work=await db.remediationWorkItem.findFirst({
  where:{id,organizationId:scope.organizationId},
  select:{id:true,title:true,status:true,revision:true,
   remediation:{select:{title:true,status:true}},
   finding:{select:{title:true,status:true,severity:true}}}
 });
 if(!work)throw new HistoryInputError("NOT_FOUND","Work item not found in this organization.");
 return work;
}
export function auditHistoryWhere(scope:AuditContext,workId:string,filter:HistoryFilter){
 const where:Prisma.RemediationWorkEventWhereInput={
  organizationId:scope.organizationId,workItemId:workId
 };
 if(filter.kind)where.kind=filter.kind as "CREATED"|"UPDATED"|"COMMENTED"|"REOPENED";
 if(filter.actorUserId)where.actorUserId=filter.actorUserId;
 if(filter.search)where.comment={contains:filter.search,mode:"insensitive"};
 if(filter.cursor)where.AND=[historyOrderWhere(filter.cursor)];
 return where;
}
export async function listWorkAuditHistory(
 scope:AuditContext,workId:string,query:Record<string,unknown>
){
 const work=await findScopedWork(scope,workId);
 const filter=parseHistoryFilter(query);
 const where=auditHistoryWhere(scope,work.id,filter);
 const [count,rows]=await db.$transaction([
  db.remediationWorkEvent.count({where}),
  db.remediationWorkEvent.findMany({
   where,select:eventSelect,
   orderBy:[{occurredAt:"desc"},{id:"desc"}],
   take:filter.limit+1
  })
 ],{isolationLevel:"RepeatableRead"});
 const page=makeHistoryPage(rows,filter.limit);
 return {
  work,page,filteredRemaining:count,
  statistics:{
   page:histogramHistory(page.rows),
   byActor:activityByActor(page.rows),
   byDay:activityDayBuckets(page.rows)
  },
  disclaimer:"This is a human work audit trail, not evidence that controls are verified."
 };
}
export async function exportWorkAuditHistory(
 scope:AuditContext,workId:string,query:Record<string,unknown>
){
 const work=await findScopedWork(scope,workId);
 const filter=parseHistoryFilter({
  ...query,limit:"100"
 });
 const where=auditHistoryWhere(scope,work.id,filter);
 const [count,rows]=await db.$transaction([
  db.remediationWorkEvent.count({where}),
  db.remediationWorkEvent.findMany({
   where,select:eventSelect,
   orderBy:[{occurredAt:"desc"},{id:"desc"}],
   take:1001
  })
 ],{isolationLevel:"RepeatableRead"});
 if(count>1000||rows.length!==count)
  throw new HistoryInputError("CAPACITY","Audit export exceeds 1,000 events. Apply filters.");
 return {work,count,body:serializeAuditHistory(rows)};
}
export async function workAuditActivitySummary(
 scope:AuditContext,workIds:readonly string[],since:Date
){
 const ids=[...new Set(workIds.map(historyIdentifier))];
 if(ids.length>100)throw new HistoryInputError("CAPACITY","At most 100 work items.");
 const rows=await db.remediationWorkEvent.findMany({
  where:{
   organizationId:scope.organizationId,workItemId:{in:ids},
   occurredAt:{gte:since}
  },
  select:{id:true,workItemId:true,kind:true,occurredAt:true,actorUserId:true,comment:true},
  orderBy:[{occurredAt:"desc"},{id:"desc"}],take:1001
 });
 if(rows.length>1000)throw new HistoryInputError("CAPACITY","Activity summary exceeds limit.");
 const counts=new Map(ids.map(id=>[id,{events:0,comments:0,updates:0,actors:new Set<string>()}]));
 for(const row of rows){
  const item=counts.get(row.workItemId);
  if(!item)continue;
  item.events++;
  if(row.kind==="COMMENTED")item.comments++;
  if(row.kind==="UPDATED"||row.kind==="REOPENED")item.updates++;
  if(row.actorUserId)item.actors.add(row.actorUserId);
 }
 return [...counts].map(([workItemId,value])=>({
  workItemId,events:value.events,comments:value.comments,
  updates:value.updates,distinctActors:value.actors.size
 }));
}
