import type {EscalationDecision,EscalationResult,EscalationLevel} from "./remediation-work-escalations";
import {WorkInputError} from "./remediation-work-input";

/**
 * Explicitly scoped escalation CSV exports.
 * CSV fields are neutralized against spreadsheet formula execution.
 * No evidence payload, notes, personal email, tokens or secrets are exported.
 */
export const MAX_ESCALATION_EXPORT=2000;
const LEVELS:readonly EscalationLevel[]=["CRITICAL","ELEVATED","WATCH","NONE"];
export const ESCALATION_COLUMNS=[
 "Work ID","Title","Revision","Operational status","Priority","Attention",
 "Attention score","Flags","Assignee ID","Assignee display name","Target date",
 "Days overdue","Days since update","Last recorded update",
 "Finding ID","Finding title","Finding severity","Finding status",
 "Remediation ID","Remediation title","Remediation status",
 "Pending responsibility handoffs","Suggested next operational action",
] as const;
export type ExportSelection={
 minLevel:EscalationLevel;
 includeClosed:boolean;
 onlyOverdue:boolean;
 maxRows:number;
};
function safeCell(value:unknown):string{
 const text=value===null||value===undefined?"":String(value);
 const sanitized=text.replace(/\u0000/g,"");
 const protectedValue=/^[\s\u0000-\u001f]*[=+@-]/.test(sanitized)
  ?"'"+sanitized:sanitized;
 return '"'+protectedValue.replace(/"/g,'""')+'"';
}
function line(cells:readonly unknown[]):string{
 return cells.map(safeCell).join(",");
}
export function parseExportSelection(raw:Record<string,unknown>):ExportSelection{
 const minLevel=raw.minLevel===undefined?"WATCH":raw.minLevel;
 if(typeof minLevel!=="string"||!LEVELS.some(level=>level===minLevel))
  throw new WorkInputError("INVALID","Unsupported export attention level.");
 const includeClosed=raw.includeClosed===true||raw.includeClosed==="true";
 const onlyOverdue=raw.onlyOverdue===true||raw.onlyOverdue==="true";
 const maxRows=raw.maxRows===undefined?MAX_ESCALATION_EXPORT:Number(raw.maxRows);
 if(!Number.isInteger(maxRows)||maxRows<1||maxRows>MAX_ESCALATION_EXPORT)
  throw new WorkInputError("INVALID","Export limit must be between 1 and 2000.");
 return {minLevel:minLevel as EscalationLevel,includeClosed,onlyOverdue,maxRows};
}
export function selectEscalationExport(
 result:EscalationResult,selection:ExportSelection,
):EscalationDecision[]{
 const threshold=LEVELS.indexOf(selection.minLevel);
 return result.decisions.filter(row=>
  LEVELS.indexOf(row.level)<=threshold &&
  (selection.includeClosed||row.level!=="NONE"||
   row.status!=="DONE"&&row.status!=="CANCELLED") &&
  (!selection.onlyOverdue||row.overdueDays!==null)
 );
}
export function escalationCsv(
 result:EscalationResult,selection:ExportSelection,
):string{
 if(!result.coverage.complete)
  throw new WorkInputError("CONFLICT","Incomplete source data cannot be exported.");
 const rows=selectEscalationExport(result,selection);
 if(rows.length>selection.maxRows)
  throw new WorkInputError("CONFLICT","Export would be incomplete. Narrow the filters.");
 const header=line(ESCALATION_COLUMNS);
 const body=rows.map(row=>line([
  row.id,row.title,row.revision,row.status,row.priority,row.level,
  row.score,row.reasons.join("; "),row.assigneeUserId,row.assigneeName,
  row.dueAt,row.overdueDays,row.idleDays,row.updatedAt,row.findingId,
  row.findingTitle,row.findingSeverity,row.findingStatus,row.remediationId,
  row.remediationTitle,row.remediationStatus,row.pendingHandoffs,row.nextAction,
 ]));
 return [
  header,...body,
 ].join("\r\n")+"\r\n";
}
export function escalationExportSummary(
 result:EscalationResult,selection:ExportSelection,
){
 const selected=selectEscalationExport(result,selection);
 return {
  exported:selected.length,
  matchingBeforeExportRules:result.summary.total,
  recordedAt:result.generatedAt,
  maxRows:selection.maxRows,
  includesClosed:selection.includeClosed,
  overdueOnly:selection.onlyOverdue,
  attentionThreshold:selection.minLevel,
  coverage:result.coverage,
  caveat:"Task escalation is coordination metadata and not verified evidence.",
 };
}
