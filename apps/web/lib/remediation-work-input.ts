/**
 * Operational work item input boundary.
 * Work status is intentionally independent of remediation workflow state.
 * Completing work does NOT verify a control, resolve a finding or update CyberScore.
 */
export const WORK_STATUSES = ["TODO", "IN_PROGRESS", "BLOCKED", "DONE", "CANCELLED"] as const;
export const WORK_PRIORITIES = ["LOW", "NORMAL", "HIGH", "URGENT"] as const;
export type WorkStatus = typeof WORK_STATUSES[number];
export type WorkPriority = typeof WORK_PRIORITIES[number];
export type WorkRole = "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
export type WorkPatch = {
  title?: string;
  description?: string;
  status?: WorkStatus;
  priority?: WorkPriority;
  assigneeUserId?: string | null;
  dueAt?: Date | null;
};
export type WorkCreate = {
  remediationId: string;
  title: string;
  description: string;
  status: WorkStatus;
  priority: WorkPriority;
  assigneeUserId: string | null;
  dueAt: Date | null;
};
export type WorkMutation =
 | {kind: "create"; value: WorkCreate}
 | {kind: "update"; id: string; revision: number; value: WorkPatch}
 | {kind: "comment"; id: string; comment: string};

export class WorkInputError extends Error {
  constructor(public readonly code: "INVALID"|"FORBIDDEN"|"MISSING"|"CONFLICT", message: string) {
    super(message);
    this.name="WorkInputError";
  }
}
export function canReadWork(role: WorkRole): boolean {
  return ["OWNER","ADMIN","MEMBER","AUDITOR"].includes(role);
}
export function canManageWork(role: WorkRole): boolean {
  return role==="OWNER"||role==="ADMIN";
}
export function canCommentWork(role: WorkRole): boolean {
  return role!=="AUDITOR";
}
export function isWorkStatus(value: unknown): value is WorkStatus {
  return typeof value==="string" && WORK_STATUSES.some(item=>item===value);
}
export function isWorkPriority(value: unknown): value is WorkPriority {
  return typeof value==="string" && WORK_PRIORITIES.some(item=>item===value);
}
export function parseWorkId(value: unknown, label="identifier"): string {
  if (typeof value!=="string" || !/^[a-zA-Z0-9_-]{5,100}$/.test(value))
    throw new WorkInputError("INVALID", `Invalid ${label}.`);
  return value;
}
export function parseWorkTitle(value: unknown): string {
  if (typeof value!=="string") throw new WorkInputError("INVALID","Title must be text.");
  const title=value.trim();
  if (title.length<3||title.length>160||/[\u0000-\u001f\u007f]/.test(title))
    throw new WorkInputError("INVALID","Title must contain 3–160 printable characters.");
  return title;
}
export function parseWorkDescription(value: unknown): string {
  if (typeof value!=="string" || value.length>4000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value))
    throw new WorkInputError("INVALID","Description must be text no longer than 4000 characters.");
  return value.trim();
}
export function parseWorkComment(value: unknown): string {
  if (typeof value!=="string") throw new WorkInputError("INVALID","Comment must be text.");
  const text=value.trim();
  if (!text || text.length>2000 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text))
    throw new WorkInputError("INVALID","Comment must contain 1–2000 printable characters.");
  return text;
}
export function parseWorkDueAt(value: unknown): Date | null {
  if (value===null || value==="") return null;
  if (typeof value!=="string" || !/^\d{4}-\d{2}-\d{2}$/.test(value))
    throw new WorkInputError("INVALID","Due date must be YYYY-MM-DD or null.");
  const parsed=new Date(`${value}T12:00:00.000Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0,10)!==value)
    throw new WorkInputError("INVALID","Due date is not a real calendar date.");
  if (parsed.getUTCFullYear()<2000||parsed.getUTCFullYear()>2100)
    throw new WorkInputError("INVALID","Due date is outside the supported range.");
  return parsed;
}
function object(value: unknown): Record<string,unknown> {
  if (!value || typeof value!=="object" || Array.isArray(value))
    throw new WorkInputError("INVALID","Expected a JSON object.");
  return value as Record<string,unknown>;
}
function rejectUnknownKeys(input: Record<string,unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) throw new WorkInputError("INVALID",`Unknown work field: ${key}.`);
  }
}
export function parseWorkCreate(input: unknown): WorkCreate {
  const data=object(input);
  rejectUnknownKeys(data,["remediationId","title","description","status","priority","assigneeUserId","dueAt"]);
  return {
    remediationId:parseWorkId(data.remediationId,"remediation ID"),
    title:parseWorkTitle(data.title),
    description:data.description===undefined?"":parseWorkDescription(data.description),
    status:data.status===undefined?"TODO":parseStatus(data.status),
    priority:data.priority===undefined?"NORMAL":parsePriority(data.priority),
    assigneeUserId:parseAssignee(data.assigneeUserId),
    dueAt:data.dueAt===undefined?null:parseWorkDueAt(data.dueAt)
  };
}
export function parseStatus(value: unknown): WorkStatus {
  if (!isWorkStatus(value)) throw new WorkInputError("INVALID","Unsupported work status.");
  return value;
}
export function parsePriority(value: unknown): WorkPriority {
  if (!isWorkPriority(value)) throw new WorkInputError("INVALID","Unsupported work priority.");
  return value;
}
export function parseAssignee(value: unknown): string|null {
  return value===undefined||value===null||value===""?null:parseWorkId(value,"assignee ID");
}
export function parseWorkPatch(input: unknown): WorkPatch {
  const data=object(input);
  rejectUnknownKeys(data,["title","description","status","priority","assigneeUserId","dueAt"]);
  const patch:WorkPatch={};
  if ("title" in data)patch.title=parseWorkTitle(data.title);
  if ("description" in data)patch.description=parseWorkDescription(data.description);
  if ("status" in data)patch.status=parseStatus(data.status);
  if ("priority" in data)patch.priority=parsePriority(data.priority);
  if ("assigneeUserId" in data)patch.assigneeUserId=parseAssignee(data.assigneeUserId);
  if ("dueAt" in data)patch.dueAt=parseWorkDueAt(data.dueAt);
  if (!Object.keys(patch).length)throw new WorkInputError("INVALID","At least one field is required.");
  return patch;
}
export function parseRevision(value: unknown): number {
  if (!Number.isInteger(value)||Number(value)<1||Number(value)>2147483647)
    throw new WorkInputError("INVALID","A positive integer revision is required.");
  return value as number;
}
export function parseWorkMutation(input: unknown): WorkMutation {
  const data=object(input);
  if (data.kind==="create") {
    rejectUnknownKeys(data,["kind","value"]);
    return {kind:"create",value:parseWorkCreate(data.value)};
  }
  if (data.kind==="update") {
    rejectUnknownKeys(data,["kind","id","revision","value"]);
    return {kind:"update",id:parseWorkId(data.id),revision:parseRevision(data.revision),value:parseWorkPatch(data.value)};
  }
  if (data.kind==="comment") {
    rejectUnknownKeys(data,["kind","id","comment"]);
    return {kind:"comment",id:parseWorkId(data.id),comment:parseWorkComment(data.comment)};
  }
  throw new WorkInputError("INVALID","Unsupported work operation.");
}
export function transitionWorkStatus(before:WorkStatus, after:WorkStatus): "UPDATE"|"REOPEN" {
  if (before===after) return "UPDATE";
  if (before==="CANCELLED"&&after!=="TODO")
    throw new WorkInputError("INVALID","Reopen cancelled work to TODO before further progress.");
  if (before==="DONE"&&after==="IN_PROGRESS") return "REOPEN";
  if (before==="DONE"&&after==="BLOCKED")return "REOPEN";
  if (before==="DONE"&&after==="TODO")return "REOPEN";
  if (after==="DONE"&&before==="CANCELLED")
    throw new WorkInputError("INVALID","Cancelled work must be reopened first.");
  return "UPDATE";
}
export type WorkFilter = {
  status:WorkStatus|"ALL";
  priority:WorkPriority|"ALL";
  assigneeUserId:string|"ALL"|"UNASSIGNED";
  due:"ALL"|"OVERDUE"|"NEXT_7_DAYS"|"NO_DATE";
  search:string;
  page:number;
  pageSize:20|50|100;
};
export function parseWorkFilter(values: Record<string,unknown>): WorkFilter {
  const status=isWorkStatus(values.status)?values.status:"ALL";
  const priority=isWorkPriority(values.priority)?values.priority:"ALL";
  const assigneeUserId=values.assignee==="UNASSIGNED"?"UNASSIGNED":
    typeof values.assignee==="string"&&/^[a-zA-Z0-9_-]{5,100}$/.test(values.assignee)
      ?values.assignee:"ALL";
  const due=["OVERDUE","NEXT_7_DAYS","NO_DATE"].includes(String(values.due))
    ?values.due as WorkFilter["due"]:"ALL";
  const search=typeof values.search==="string"?values.search.trim().slice(0,120):"";
  const page=typeof values.page==="string"&&/^\d{1,7}$/.test(values.page)
    ?Math.max(1,Math.min(1000000,Number(values.page))):1;
  const pageSize=values.pageSize==="50"?50:values.pageSize==="100"?100:20;
  return {status,priority,assigneeUserId,due,search,page,pageSize};
}
export function deriveWorkDue(now:Date,dueAt:Date|null,status:WorkStatus):"NONE"|"OVERDUE"|"SOON"|"ON_TRACK"|"CLOSED"{
  if (status==="DONE"||status==="CANCELLED")return "CLOSED";
  if (!dueAt)return "NONE";
  const at=dueAt.getTime(),current=now.getTime();
  if (at<current)return "OVERDUE";
  if (at-current<=7*86400000)return "SOON";
  return "ON_TRACK";
}
export function workSummary<T extends {status:WorkStatus;dueAt:Date|null}>(items:readonly T[],now=new Date()){
  const summary={total:items.length,todo:0,working:0,blocked:0,done:0,cancelled:0,overdue:0,dueSoon:0};
  for (const item of items) {
    if(item.status==="TODO")summary.todo++;
    if(item.status==="IN_PROGRESS")summary.working++;
    if(item.status==="BLOCKED")summary.blocked++;
    if(item.status==="DONE")summary.done++;
    if(item.status==="CANCELLED")summary.cancelled++;
    const due=deriveWorkDue(now,item.dueAt,item.status);
    if(due==="OVERDUE")summary.overdue++;
    if(due==="SOON")summary.dueSoon++;
  }
  return summary;
}
