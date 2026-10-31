export type ActionQueueRow={
 id:string;title:string;status:string;mode:string;severity:string;findingStatus:string;
 createdAt:Date;verifiedAt:Date|null;stepCount:number;acknowledgedCount:number;
};
export type ActionQueueBucket="verify"|"failed"|"unstarted"|"working"|"verified"|"other";
export type ActionQueueItem=ActionQueueRow&{
 bucket:ActionQueueBucket;priority:number;nextAction:string;progressPercent:number|null;
};
const severityRanks:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
export function classifyActionQueue(row:ActionQueueRow):ActionQueueItem{
 const allStepsDone=row.mode==="GUIDED"&&row.stepCount>0&&row.acknowledgedCount>=row.stepCount;
 const verified=row.status==="VERIFIED"&&row.verifiedAt!==null;
 const bucket:ActionQueueBucket=verified?"verified":
  row.status==="FAILED"?"failed":
  row.status==="SUCCEEDED"||allStepsDone?"verify":
  row.status==="PROPOSED"?"unstarted":
  row.status==="APPROVED"||row.status==="EXECUTING"?"working":"other";
 const actions:Record<ActionQueueBucket,string>={
  verify:"Request fresh evidence; acknowledged work is not proof of security.",
  failed:"Review the failure before attempting remediation again.",
  unstarted:"Review and approve the proposed remediation plan.",
  working:"Continue approved work and record completed steps.",
  verified:"Review the recorded verification and associated finding.",
  other:"Review the action status and the latest supporting evidence.",
 };
 const bucketRank:Record<ActionQueueBucket,number>={verify:0,failed:1,unstarted:2,working:3,other:4,verified:5};
 const severityRank=severityRanks[row.severity]??5;
 return {...row,bucket,priority:bucketRank[bucket]*10+severityRank,nextAction:actions[bucket],
  progressPercent:row.stepCount>0?Math.min(100,Math.round(row.acknowledgedCount/row.stepCount*100)):null};
}
export function prioritizeActionQueue(rows:readonly ActionQueueRow[]):ActionQueueItem[]{
 return rows.map(classifyActionQueue).sort((a,b)=>
  a.priority-b.priority||a.createdAt.getTime()-b.createdAt.getTime()||a.id.localeCompare(b.id));
}
export function summarizeActionQueue(items:readonly ActionQueueItem[]){
 const counts={verify:0,failed:0,unstarted:0,working:0,verified:0,other:0};
 for(const item of items)counts[item.bucket]++;
 return {...counts,total:items.length,needsAttention:counts.verify+counts.failed+counts.unstarted};
}
