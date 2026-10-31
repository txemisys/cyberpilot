/**
 * Organization-wide audit feed policy: tenant-local activity with an explicit
 * fixed time window and stable ordering. No activity event proves remediation success.
 */
import {historyIdentifier,HistoryInputError,type HistoryRow} from "./work-audit-history";
export type FeedFilter={
 workItemId:string|null;actorUserId:string|null;kind:string|null;
 days:7|30|90;limit:10|25|50|100;
};
export type FeedRow=HistoryRow&{
 workItemId:string;workItem:{title:string;status:string;
  finding:{title:string;status:string;severity:string}};
 actor:{name:string;email:string}|null;
};
export function parseFeedFilter(input:Record<string,unknown>):FeedFilter{
 const allowed=["work","actor","kind","days","limit"];
 if(Object.keys(input).some(k=>!allowed.includes(k)))
  throw new HistoryInputError("INVALID","Unsupported organization audit filter.");
 const days=input.days===undefined?"30":input.days;
 if(days!=="7"&&days!=="30"&&days!=="90")
  throw new HistoryInputError("INVALID","Audit window must be 7, 30 or 90 days.");
 const size=input.limit===undefined?"25":input.limit;
 if(size!=="10"&&size!=="25"&&size!=="50"&&size!=="100")
  throw new HistoryInputError("INVALID","Audit page size must be 10, 25, 50 or 100.");
 const kind=input.kind===undefined||input.kind==="ALL"?null:input.kind;
 if(kind!==null&&!["CREATED","UPDATED","COMMENTED","REOPENED"].includes(String(kind)))
  throw new HistoryInputError("INVALID","Invalid audit event kind.");
 return {
  workItemId:input.work?historyIdentifier(input.work):null,
  actorUserId:input.actor?historyIdentifier(input.actor):null,
  kind:kind as string|null,days:Number(days) as FeedFilter["days"],
  limit:Number(size) as FeedFilter["limit"]
 };
}
export function feedSince(now:Date,days:7|30|90):Date{
 return new Date(now.getTime()-days*86400000);
}
export function countFeedConcerns(rows:readonly FeedRow[]){
 const summary={total:rows.length,anonymous:0,completedWorkOpenFindings:0,
  comments:0,updates:0,distinctTasks:0};
 const tasks=new Set<string>();
 for(const row of rows){
  tasks.add(row.workItemId);
  if(!row.actorUserId)summary.anonymous++;
  if(row.workItem.status==="DONE"&&row.workItem.finding.status==="OPEN")
   summary.completedWorkOpenFindings++;
  if(row.kind==="COMMENTED")summary.comments++;
  if(row.kind==="UPDATED"||row.kind==="REOPENED")summary.updates++;
 }
 summary.distinctTasks=tasks.size;
 return {...summary,disclaimer:"Activity volume and work completion do not verify controls."};
}
export function groupFeedByWork(rows:readonly FeedRow[]){
 const map=new Map<string,{title:string;events:number;comments:number;lastAt:Date;
  findingStatus:string;workStatus:string}>();
 for(const row of rows){
  const group=map.get(row.workItemId)??{
   title:row.workItem.title,events:0,comments:0,lastAt:row.occurredAt,
   findingStatus:row.workItem.finding.status,workStatus:row.workItem.status
  };
  group.events++;
  if(row.kind==="COMMENTED")group.comments++;
  if(row.occurredAt>group.lastAt)group.lastAt=row.occurredAt;
  map.set(row.workItemId,group);
 }
 return [...map].map(([workItemId,summary])=>({workItemId,...summary}))
  .sort((a,b)=>b.events-a.events||a.workItemId.localeCompare(b.workItemId));
}
export function serializeFeedDigest(rows:readonly FeedRow[]){
 return rows.map(row=>({
  eventId:row.id,workItemId:row.workItemId,
  kind:row.kind,at:row.occurredAt.toISOString(),
  title:row.workItem.title,actor:row.actor?.name??null,
  findingStatus:row.workItem.finding.status,
  workStatus:row.workItem.status,comment:row.comment,
  warning:row.workItem.status==="DONE"&&row.workItem.finding.status==="OPEN"?
   "Human work complete, finding remains open.":null
 }));
}
