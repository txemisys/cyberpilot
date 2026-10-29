import type { ActionTrendReport } from "./evidence-action-trend-report";
/** Validate executive signal labels against actual numeric changes; offline only. */
export type TrendReportAudit = {ok:boolean;issues:string[]};
const changes=["completed","open","overdue","alerts","acceptedEvents"] as const;
const sign=(value:number,positive:string,negative:string)=>value>0?positive:value<0?negative:null;
export function auditActionTrendReport(report:ActionTrendReport,organizationId:string):TrendReportAudit {
 const issues:string[]=[];
 if(!organizationId||report.organizationId!==organizationId)issues.push("TENANT_MISMATCH");
 if(!/^\d{4}-\d{2}-\d{2}$/.test(report.period.from)||!/^\d{4}-\d{2}-\d{2}$/.test(report.period.to)||report.period.from>report.period.to||
 !Number.isSafeInteger(report.period.points)||report.period.points<1||report.period.points>366)issues.push("INVALID_PERIOD");
 if(changes.some(k=>!Number.isSafeInteger(report.metrics[k])))issues.push("INVALID_METRICS");
 const required=[
 sign(report.metrics.completed,"COMPLETION_GAIN","COMPLETION_LOSS"),
 sign(report.metrics.overdue,"OVERDUE_INCREASE","OVERDUE_DECREASE"),
 sign(report.metrics.alerts,"ALERT_INCREASE","ALERT_DECREASE"),
 ].filter((x):x is string=>x!==null);
 const expected=required.length?required:["NO_SIGNIFICANT_CHANGE"];
 if(!Array.isArray(report.signals)||report.signals.length!==expected.length||
 expected.some(x=>!report.signals.includes(x))||new Set(report.signals).size!==report.signals.length)issues.push("SIGNAL_MISMATCH");
 return {ok:issues.length===0,issues};
}
