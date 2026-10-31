import {WorkInputError} from "./remediation-work-input";
import type {GateDecision,GateReview,GateLevel,GateIssue} from "./remediation-work-readiness";

/** CSV exports are neutralized for formula injection and refuse partial results. */
export const READINESS_EXPORT_COLUMNS=[
 "Work ID","Work title","Revision","Status","Priority","Readiness level",
 "Operational flags","Responsible member ID","Responsible name",
 "Checklist steps","Completed checklist","Remaining checklist",
 "Active evidence references","Pending handoffs","Due date","Overdue days",
 "Finding ID","Finding title","Finding status","Finding severity",
 "Remediation ID","Remediation title","Remediation status",
 "Recommended human action",
] as const;
export type ReadinessExportSelection={
 level:GateLevel|"ALL";issue:GateIssue|"ALL";maxRows:number;
};
const levels:GateLevel[]=[
 "READY_FOR_HUMAN_REVIEW","REQUIRES_ATTENTION","BLOCKED","CLOSED_REVIEW",
];
const issues:GateIssue[]=[
 "NO_OWNER","NO_CHECKLIST","INCOMPLETE_CHECKLIST","NO_EVIDENCE","PENDING_HANDOFF",
 "BLOCKED","OVERDUE","UNCONFIRMED_FINDING","CLOSED_WITH_GAPS",
];
export function parseReadinessExportSelection(raw:Record<string,unknown>):ReadinessExportSelection{
 const level=raw.level===undefined?"ALL":raw.level;
 const issue=raw.issue===undefined?"ALL":raw.issue;
 const maxRows=raw.maxRows===undefined?2000:Number(raw.maxRows);
 if(level!=="ALL"&&(typeof level!=="string"||!levels.includes(level as GateLevel)))
  throw new WorkInputError("INVALID","Unknown readiness export level.");
 if(issue!=="ALL"&&(typeof issue!=="string"||!issues.includes(issue as GateIssue)))
  throw new WorkInputError("INVALID","Unknown readiness export issue.");
 if(!Number.isSafeInteger(maxRows)||maxRows<1||maxRows>2000)
  throw new WorkInputError("INVALID","Export limit must be from 1 to 2000.");
 return {level:level as ReadinessExportSelection["level"],
  issue:issue as ReadinessExportSelection["issue"],maxRows};
}
function csvCell(value:unknown):string{
 const raw=value===null||value===undefined?"":String(value);
 const withoutNull=raw.replace(/\u0000/g,"");
 const protectedValue=/^[\s]*[=+@-]/.test(withoutNull)?"'"+withoutNull:withoutNull;
 return '"'+protectedValue.replace(/"/g,'""')+'"';
}
function csvLine(values:readonly unknown[]):string{
 return values.map(csvCell).join(",");
}
export function selectReadinessExport(
 review:GateReview,selection:ReadinessExportSelection,
):GateDecision[]{
 return review.rows.filter(item=>
  (selection.level==="ALL"||item.level===selection.level)&&
  (selection.issue==="ALL"||item.issues.includes(selection.issue as GateIssue)));
}
export function readinessCsv(review:GateReview,selection:ReadinessExportSelection):string{
 if(!review.coverage.complete)
  throw new WorkInputError("CONFLICT","Cannot export incomplete readiness review.");
 const rows=selectReadinessExport(review,selection);
 if(rows.length>selection.maxRows)
  throw new WorkInputError("CONFLICT","Export exceeds row limit. Narrow filters.");
 return [csvLine(READINESS_EXPORT_COLUMNS),...rows.map(item=>csvLine([
  item.id,item.title,item.revision,item.status,item.priority,item.level,
  item.issues.join("; "),item.assigneeUserId,item.assigneeName,
  item.totalChecklist,item.completedChecklist,item.remainingChecklist,
  item.activeEvidenceLinks,item.pendingHandoffs,item.dateDue,item.overdueDays,
  item.findingId,item.findingTitle,item.findingStatus,item.findingSeverity,
  item.remediationId,item.remediationTitle,item.remediationStatus,item.recommendation,
 ]))].join("\r\n")+"\r\n";
}
