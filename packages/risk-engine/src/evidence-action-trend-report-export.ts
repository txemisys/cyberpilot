import type { ActionTrendReport } from "./evidence-action-trend-report";
/** Safe read-only CSV/JSON export of a tenant-bound trend report. */
export type ActionTrendReportExport={ok:true;format:"csv"|"json";filename:string;content:string}|{ok:false;error:"TENANT_MISMATCH"|"INVALID_REPORT"};
const validDate=(s:string)=>/^\d{4}-\d{2}-\d{2}$/.test(s)&&Number.isFinite(Date.parse(s+"T00:00:00Z"))&&new Date(s+"T00:00:00Z").toISOString().slice(0,10)===s;
const keys=["completed","open","overdue","alerts","acceptedEvents"] as const;
const signals=new Set(["COMPLETION_GAIN","COMPLETION_LOSS","OVERDUE_INCREASE","OVERDUE_DECREASE","ALERT_INCREASE","ALERT_DECREASE","NO_SIGNIFICANT_CHANGE"]);
const csv=(value:string)=>'"'+(/^[\s]*[=+@\-]/.test(value)?"'"+value:value).replace(/"/g,'""')+'"';
export function exportActionTrendReport(report:ActionTrendReport,organizationId:string,format:"csv"|"json"):ActionTrendReportExport {
 if(!organizationId||report.organizationId!==organizationId)return {ok:false,error:"TENANT_MISMATCH"};
 if(!validDate(report.period.from)||!validDate(report.period.to)||report.period.from>report.period.to||
 !Number.isSafeInteger(report.period.points)||report.period.points<1||report.period.points>366||
 keys.some(k=>!Number.isSafeInteger(report.metrics[k]))||
 !Array.isArray(report.signals)||report.signals.length===0||
 report.signals.some(x=>!signals.has(x))||new Set(report.signals).size!==report.signals.length||
 (report.signals.includes("NO_SIGNIFICANT_CHANGE")&&(report.signals.length!==1||keys.some(k=>report.metrics[k]!==0))))return {ok:false,error:"INVALID_REPORT"};
 if(format==="json")return {ok:true,format,filename:"action-trend-report.json",content:JSON.stringify({schemaVersion:1,organizationId,period:report.period,metrics:report.metrics,signals:report.signals})};
 const rows=[["organizationId",organizationId],["from",report.period.from],["to",report.period.to],["points",String(report.period.points)],...keys.map(k=>[k,String(report.metrics[k])]),["signals",report.signals.join(";")]];
 return {ok:true,format,filename:"action-trend-report.csv",content:"field,value\r\n"+rows.map(r=>r.map(csv).join(",")).join("\r\n")+"\r\n"};
}
