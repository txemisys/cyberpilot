import type { ActionPageInput } from "./action-pagination";
export type RemediationExportRow = {
 id:string;title:string;status:string;mode:string;severity:string;findingTitle:string;
 findingStatus:string;createdAt:Date;approvedAt:Date|null;startedAt:Date|null;
 completedAt:Date|null;verifiedAt:Date|null;guidedCompleted:number;
 guidedTotal:number;needsVerification:boolean;
};
const headings=["Remediation ID","Title","Status","Mode","Severity","Finding","Finding status","Created UTC","Approved UTC","Started UTC","Completed UTC","Verified UTC","Steps acknowledged","Steps total","Needs verification"];
const encode=(value:string)=>{
 const neutralized=/^[\s]*[=+@\-\t\r\n]/.test(value)?"'"+value:value;
 return '"'+neutralized.replaceAll('"','""')+'"';
};
const iso=(date:Date|null)=>date?date.toISOString():"";
export function serializeRemediationExport(rows:readonly RemediationExportRow[]):string {
 const lines=rows.map(row=>[
  row.id,row.title,row.status,row.mode,row.severity,row.findingTitle,row.findingStatus,
  iso(row.createdAt),iso(row.approvedAt),iso(row.startedAt),iso(row.completedAt),iso(row.verifiedAt),
  String(row.guidedCompleted),String(row.guidedTotal),row.needsVerification?"YES":"NO",
 ].map(encode).join(","));
 return "\uFEFF"+[headings.map(encode).join(","),...lines].join("\r\n")+"\r\n";
}
export function describeRemediationExport(settings:ActionPageInput,count:number):string {
 const state=settings.status==="all"?"all states":settings.status;
 const priority=settings.severity==="ALL"?"all severities":settings.severity;
 return `Exported ${count} action records with ${state}, ${priority}${settings.search?", text search applied":""}. This is an operational report, not verification of security improvements.`;
}
