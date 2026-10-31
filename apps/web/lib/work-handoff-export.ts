/**
 * Reviewable handoff export for managers and recipients.
 * All rows represent a request and decision, not a completed remediation.
 */
export type HandoffExportRow={
 id:string;workItemId:string;status:string;reason:string;response:string|null;
 requester:{name:string;email:string}|null;recipient:{name:string;email:string};
 decider:{name:string;email:string}|null;
 workItem:{title:string;status:string;finding:{title:string;status:string;severity:string}};
 requestedAt:Date;expiresAt:Date|null;decidedAt:Date|null;revision:number;
};
export const HANDOFF_COLUMNS=[
 "Request ID","Work ID","Work title","Work state",
 "Finding","Finding severity","Finding state",
 "Request state","Reason","Response",
 "Requested by","Requester email","Recipient","Recipient email",
 "Decided by","Decision actor email","Requested UTC","Expires UTC","Decided UTC","Revision"
] as const;
const formula=/^[\s\u0000-\u001f]*[=+@\-]/;
export function csvHandoffCell(input:string|number):string{
 const value=String(input);
 const safe=formula.test(value)?"'"+value:value;
 return '"'+safe.replaceAll('"','""')+'"';
}
export function handoffDate(date:Date|null):string{
 return date instanceof Date&&!Number.isNaN(date.getTime())?date.toISOString():"";
}
export function handoffValues(row:HandoffExportRow):Array<string|number>{
 return [
  row.id,row.workItemId,row.workItem.title,row.workItem.status,
  row.workItem.finding.title,row.workItem.finding.severity,row.workItem.finding.status,
  row.status,row.reason,row.response??"",
  row.requester?.name??"",row.requester?.email??"",
  row.recipient.name,row.recipient.email,
  row.decider?.name??"",row.decider?.email??"",
  handoffDate(row.requestedAt),handoffDate(row.expiresAt),
  handoffDate(row.decidedAt),row.revision
 ];
}
export function serializeHandoffs(rows:readonly HandoffExportRow[]):string{
 const records=rows.map(row=>handoffValues(row).map(csvHandoffCell).join(","));
 return [HANDOFF_COLUMNS.map(csvHandoffCell).join(","),...records].join("\r\n")+"\r\n";
}
export function summarizeHandoffExport(rows:readonly HandoffExportRow[]){
 const result={total:rows.length,requested:0,accepted:0,declined:0,cancelled:0,
  acceptedWithOpenFindings:0,completedWorkWithOpenFindings:0};
 for(const row of rows){
  if(row.status==="REQUESTED")result.requested++;
  if(row.status==="ACCEPTED")result.accepted++;
  if(row.status==="DECLINED")result.declined++;
  if(row.status==="CANCELLED")result.cancelled++;
  if(row.status==="ACCEPTED"&&row.workItem.finding.status==="OPEN")
   result.acceptedWithOpenFindings++;
  if(row.workItem.status==="DONE"&&row.workItem.finding.status==="OPEN")
   result.completedWorkWithOpenFindings++;
 }
 return {...result,note:"Handoff acceptance is not remediation verification or finding resolution."};
}
export type HandoffInboxRow={
 id:string;recipientUserId:string;requesterUserId:string|null;
 status:string;requestedAt:Date;expiresAt:Date|null;
 workItem:{status:string;priority:string;dueAt:Date|null};
};
export type HandoffAttention={
 id:string;urgency:"EXPIRED"|"OVERDUE_WORK"|"DUE_SOON"|"AWAITING"|"CLOSED";
 actionable:boolean;message:string;
};
export function classifyHandoffAttention(row:HandoffInboxRow,now=new Date()):HandoffAttention{
 if(row.status!=="REQUESTED")
  return {id:row.id,urgency:"CLOSED",actionable:false,message:"Decision recorded."};
 if(row.expiresAt&&row.expiresAt<now)
  return {id:row.id,urgency:"EXPIRED",actionable:false,
   message:"Request expired; manager must issue a new request."};
 if(row.workItem.dueAt&&row.workItem.dueAt<now&&row.workItem.status!=="DONE")
  return {id:row.id,urgency:"OVERDUE_WORK",actionable:true,
   message:"The underlying work is overdue while assignment is awaiting acceptance."};
 if(row.workItem.dueAt&&row.workItem.dueAt.getTime()-now.getTime()<=7*86400000&&
  row.workItem.status!=="DONE")
  return {id:row.id,urgency:"DUE_SOON",actionable:true,
   message:"Work deadline is within seven days; review assignment request."};
 return {id:row.id,urgency:"AWAITING",actionable:true,
  message:"Recipient has not yet accepted or declined responsibility."};
}
export function prioritizeHandoffAttention(rows:readonly HandoffInboxRow[],now=new Date()){
 const rank={EXPIRED:0,OVERDUE_WORK:1,DUE_SOON:2,AWAITING:3,CLOSED:4};
 return rows.map(row=>({...row,attention:classifyHandoffAttention(row,now)}))
  .sort((a,b)=>rank[a.attention.urgency]-rank[b.attention.urgency]||
   a.requestedAt.getTime()-b.requestedAt.getTime()||a.id.localeCompare(b.id));
}
export function groupHandoffInbox(rows:readonly HandoffInboxRow[],now=new Date()){
 const people=new Map<string,{total:number;waiting:number;overdue:number;expiring:number}>();
 for(const row of rows){
  const key=row.recipientUserId;
  const summary=people.get(key)??{total:0,waiting:0,overdue:0,expiring:0};
  summary.total++;
  const attention=classifyHandoffAttention(row,now);
  if(attention.actionable)summary.waiting++;
  if(attention.urgency==="OVERDUE_WORK")summary.overdue++;
  if(attention.urgency==="EXPIRED")summary.expiring++;
  people.set(key,summary);
 }
 return [...people].map(([recipientUserId,counts])=>({recipientUserId,...counts}))
  .sort((a,b)=>b.overdue-a.overdue||b.waiting-a.waiting||
   a.recipientUserId.localeCompare(b.recipientUserId));
}
