import {WorkInputError} from "./remediation-work-input";
import type {DigestResult,DigestItem} from "./remediation-work-digest";

/** Stable formula-safe exports of bounded operational snapshots. */
export type DigestExportOptions={mode:"PRIORITIES"|"FOLLOW_UPS";maxRows:number;onlyAttention:boolean};
export const DIGEST_PRIORITY_COLUMNS=[
 "Work ID","Title","Status","Priority","Owner","Target date","Attention index",
 "Attention reasons","Overdue days","Idle days","Checklist completed",
 "Checklist total","Active evidence references","Pending handoffs",
] as const;
export const DIGEST_FOLLOW_UP_COLUMNS=[
 "Operational signal","Affected work count","Recommended human follow up",
] as const;
export function parseDigestExportOptions(raw:unknown):DigestExportOptions{
 if(raw===null||typeof raw!=="object"||Array.isArray(raw))
  throw new WorkInputError("INVALID","Digest export options must be an object.");
 const data=raw as Record<string,unknown>;
 for(const key of Object.keys(data))
  if(!["mode","maxRows","onlyAttention"].includes(key))
   throw new WorkInputError("INVALID",`Unsupported export setting: ${key}.`);
 const mode=data.mode===undefined?"PRIORITIES":data.mode;
 const maxRows=data.maxRows===undefined?100:data.maxRows;
 const onlyAttention=data.onlyAttention===undefined?false:data.onlyAttention;
 if(mode!=="PRIORITIES"&&mode!=="FOLLOW_UPS")
  throw new WorkInputError("INVALID","Unsupported digest export mode.");
 if(typeof maxRows!=="number"||!Number.isSafeInteger(maxRows)||maxRows<1||maxRows>100)
  throw new WorkInputError("INVALID","Digest export supports 1–100 rows.");
 if(typeof onlyAttention!=="boolean")
  throw new WorkInputError("INVALID","Attention-only flag must be boolean.");
 return {mode,maxRows,onlyAttention};
}
function csvCell(value:unknown):string{
 const valueString=value===null||value===undefined?"":String(value);
 const withoutNull=valueString.replace(/\u0000/g,"");
 const safe=/^\s*[=+@-]/.test(withoutNull)?"'"+withoutNull:withoutNull;
 return '"'+safe.replace(/"/g,'""')+'"';
}
function line(values:readonly unknown[]):string{return values.map(csvCell).join(",");}
export function selectedDigestRows(report:DigestResult,onlyAttention:boolean):DigestItem[]{
 return report.priorities.filter(item=>!onlyAttention||item.reasons.length>0);
}
export function digestCsv(report:DigestResult,options:DigestExportOptions):string{
 if(!report.coverage.complete)
  throw new WorkInputError("CONFLICT","Digest is incomplete; export refused.");
 if(options.mode==="FOLLOW_UPS"){
  const rows=report.followUps;
  if(rows.length>options.maxRows)
   throw new WorkInputError("CONFLICT","Follow-up export exceeds limit.");
  return [line(DIGEST_FOLLOW_UP_COLUMNS),...rows.map(item=>
   line([item.kind,item.count,item.recommendation]))].join("\r\n")+"\r\n";
 }
 if(report.coverage.excludedFromPreview>0)
  throw new WorkInputError("CONFLICT",
   "Digest priorities preview is truncated; increase display limit or narrow scope.");
 const rows=selectedDigestRows(report,options.onlyAttention);
 if(rows.length>options.maxRows)
  throw new WorkInputError("CONFLICT","Export exceeds explicit maximum rows.");
 return [line(DIGEST_PRIORITY_COLUMNS),...rows.map(row=>line([
  row.id,row.title,row.status,row.priority,row.owner,row.dueAt,row.weight,
  row.reasons.join("; "),row.daysOverdue,row.daysIdle,row.checklistDone,
  row.checklistTotal,row.activeEvidence,row.pendingHandoffs,
 ]))].join("\r\n")+"\r\n";
}
export function digestIntegrity(report:DigestResult){
 const counts=report.summary;
 return {balanced:counts.open+counts.closed===counts.total,
  previewIsBounded:report.priorities.length<=report.config.maxItems,
  complete:report.coverage.complete,
  hasExcludedPreviewItems:report.coverage.excludedFromPreview>0,
  asOf:report.generatedAt,
  note:"Internal work-record count consistency only; no security testing.",
 };
}
