/**
 * Evidence-safe operational checklist export.
 * This snapshot is a record of human acknowledgment and must never be described
 * as a compliance attestation, security observation or verification outcome.
 */
export type ChecklistExportRecord={
 position:number;title:string;description:string;
 completedAt:Date|null;completedBy:{name:string;email:string}|null;
 createdAt:Date;updatedAt:Date;
};
export const CHECKLIST_EXPORT_COLUMNS=[
 "Step number","Coordination step","Instructions","Acknowledged",
 "Acknowledged timestamp (UTC)","Acknowledged by","Acknowledged by email",
 "Created (UTC)","Updated (UTC)"
] as const;
const FORMULA=/^[\s\u0000-\u001f]*[=+@\-]/;
function cell(value:string|number):string{
 const raw=String(value);
 const protectedValue=FORMULA.test(raw)?"'"+raw:raw;
 return '"'+protectedValue.replaceAll('"','""')+'"';
}
function iso(value:Date|null):string{
 return value!==null&&!Number.isNaN(value.getTime())?value.toISOString():"";
}
export function checklistCsvRows(records:readonly ChecklistExportRecord[]):string[][]{
 return records.map(entry=>[
  String(entry.position+1),entry.title,entry.description,
  entry.completedAt?"YES":"NO",iso(entry.completedAt),
  entry.completedBy?.name??"",entry.completedBy?.email??"",
  iso(entry.createdAt),iso(entry.updatedAt)
 ]);
}
export function buildChecklistCsv(records:readonly ChecklistExportRecord[]):string{
 return [
  CHECKLIST_EXPORT_COLUMNS.map(cell).join(","),
  ...checklistCsvRows(records).map(row=>row.map(cell).join(","))
 ].join("\r\n")+"\r\n";
}
export function checklistFilename(workItemId:string):string{
 const safe=workItemId.replace(/[^a-zA-Z0-9_-]/g,"_").slice(0,100);
 return `cyberpilot-work-checklist-${safe}.csv`;
}
export function checklistCoverage(records:readonly ChecklistExportRecord[]){
 const total=records.length;
 const acknowledged=records.filter(x=>x.completedAt!==null).length;
 return {
  total,acknowledged,pending:total-acknowledged,
  allHumanStepsAcknowledged:total>0&&acknowledged===total,
  note:"Acknowledged steps are work coordination only, not verified controls."
 };
}
