/**
 * Streaming-safe CSV serialization of operational work data.
 * Exports reflect work tracking only; a DONE task is never a verified security control.
 */
export const WORK_EXPORT_COLUMNS=[
  "Work ID","Title","Description","Work status","Coordination priority",
  "Assignee","Assignee email","Deadline","Work due classification",
  "Remediation","Remediation status","Finding","Finding severity",
  "Finding status","Created","Updated","Completed","Revision"
] as const;
export type WorkExportRow={
  id:string;title:string;description:string;status:string;priority:string;
  assignee:{name:string;email:string}|null;dueAt:Date|null;dueState:string;
  remediation:{title:string;status:string};
  finding:{title:string;severity:string;status:string};
  createdAt:Date;updatedAt:Date;completedAt:Date|null;revision:number;
};
const DANGEROUS=/^[\s\u0000-\u001f]*[=+@\-]/;
function csvCell(value:string|number|null):string{
  const raw=value===null?"":String(value);
  // Prefix formulas (including whitespace-prefixed) to avoid execution in spreadsheet apps.
  const safe=DANGEROUS.test(raw)?"'"+raw:raw;
  return '"'+safe.replace(/"/g,'""')+'"';
}
function date(value:Date|null):string{
  return value instanceof Date&&!Number.isNaN(value.getTime())?value.toISOString():"";
}
export function workExportValues(row:WorkExportRow):Array<string|number|null>{
  return [
    row.id,row.title,row.description,row.status,row.priority,
    row.assignee?.name??"",row.assignee?.email??"",
    date(row.dueAt),row.dueState,
    row.remediation.title,row.remediation.status,
    row.finding.title,row.finding.severity,row.finding.status,
    date(row.createdAt),date(row.updatedAt),date(row.completedAt),row.revision
  ];
}
export function buildWorkCsv(rows:readonly WorkExportRow[]):string{
  return [
    WORK_EXPORT_COLUMNS.map(csvCell).join(","),
    ...rows.map(row=>workExportValues(row).map(csvCell).join(","))
  ].join("\r\n")+"\r\n";
}
export function exportFileName(slug:string,at:Date):string{
  const safeSlug=slug.replace(/[^a-zA-Z0-9_-]/g,"_").slice(0,80);
  return `cyberpilot-work-${safeSlug}-${at.toISOString().slice(0,10)}.csv`;
}
