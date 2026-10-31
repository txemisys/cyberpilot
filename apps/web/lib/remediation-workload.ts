export type WorkloadEvent = {createdAt:Date;verifiedAt:Date|null;status:string};
export type MonthlyWorkload = {month:string;created:number;verified:number};
export type WorkloadSummary = {total:number;verified:number;pending:number;inProgress:number;failed:number;other:number};
export type StatusTotal = {status:string;count:number};

export function summarizeWorkload(statuses:readonly StatusTotal[]):WorkloadSummary {
 const counts=new Map<string,number>();
 for(const row of statuses)counts.set(row.status,(counts.get(row.status)??0)+row.count);
 const total=[...counts.values()].reduce((sum,n)=>sum+n,0);
 const verified=counts.get("VERIFIED")??0;
 const pending=(counts.get("PROPOSED")??0)+(counts.get("APPROVED")??0);
 const inProgress=counts.get("EXECUTING")??0;
 const failed=counts.get("FAILED")??0;
 return {total,verified,pending,inProgress,failed,other:Math.max(0,total-verified-pending-inProgress-failed)};
}

/** Counts the creation and evidence-verification months separately. */
export function buildMonthlyWorkload(events:readonly WorkloadEvent[],limit=12):MonthlyWorkload[] {
 const totals=new Map<string,{created:number;verified:number}>();
 const increment=(date:Date,field:"created"|"verified")=>{
  if(!Number.isFinite(date.getTime()))return;
  const key=date.toISOString().slice(0,7);
  const value=totals.get(key)??{created:0,verified:0};
  value[field]++;
  totals.set(key,value);
 };
 for(const event of events){
  increment(event.createdAt,"created");
  if(event.status==="VERIFIED"&&event.verifiedAt)increment(event.verifiedAt,"verified");
 }
 return [...totals].sort(([a],[b])=>b.localeCompare(a))
  .slice(0,limit).map(([month,value])=>({month,...value}));
}
export function workloadClosureRate(summary:WorkloadSummary):number|null {
 return summary.total===0?null:Math.round(summary.verified/summary.total*100);
}
export function createWorkloadCsv(rows:readonly MonthlyWorkload[]):string {
 const values=["Month UTC,Actions created,Actions verified",...rows.map(row=>
  [row.month,row.created,row.verified].join(",")
 )];
 return "\uFEFF"+values.join("\r\n")+"\r\n";
}
