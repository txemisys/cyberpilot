import type { ActionWorkspaceTrend } from "./evidence-action-workspace-trend";
/** Read-only tenant-scoped executive trend report; no persistence or providers. */
export type ActionTrendReport={organizationId:string;period:{from:string;to:string;points:number};metrics:{completed:number;open:number;overdue:number;alerts:number;acceptedEvents:number};signals:string[]};
export function buildActionTrendReport(trend:ActionWorkspaceTrend,organizationId:string):ActionTrendReport|null {
 if(!organizationId||trend.organizationId!==organizationId||trend.points<1||
 trend.changes.length!==trend.points-1||trend.from>trend.to)return null;
 const keys=["completed","open","overdue","alerts","acceptedEvents"] as const;
 if(keys.some(key=>!Number.isSafeInteger(trend.totals[key])||trend.changes.reduce((sum,x)=>sum+x[key],0)!==trend.totals[key]))return null;
 if(trend.changes.some((x,i)=>x.from>x.to||(i===0?x.from!==trend.from:x.from!==trend.changes[i-1]!.to)))return null;
 if(trend.changes.length&&trend.changes[trend.changes.length-1]!.to!==trend.to)return null;
 const signals:string[]=[];
 if(trend.totals.completed>0)signals.push("COMPLETION_GAIN");
 if(trend.totals.completed<0)signals.push("COMPLETION_LOSS");
 if(trend.totals.overdue>0)signals.push("OVERDUE_INCREASE");
 if(trend.totals.overdue<0)signals.push("OVERDUE_DECREASE");
 if(trend.totals.alerts>0)signals.push("ALERT_INCREASE");
 if(trend.totals.alerts<0)signals.push("ALERT_DECREASE");
 if(signals.length===0)signals.push("NO_SIGNIFICANT_CHANGE");
 return {organizationId,period:{from:trend.from,to:trend.to,points:trend.points},metrics:{...trend.totals},signals};
}
