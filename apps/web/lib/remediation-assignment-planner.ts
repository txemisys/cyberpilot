import { db } from "@cyberpilot/database";
import { canManageWork, WorkInputError, type WorkPriority, type WorkStatus } from "./remediation-work-input";
import type { WorkContext } from "./remediation-work-store";

/**
 * Assignment planning is a decision aid, not a staffing assessment.
 * Capacity is an explicit user-supplied scenario parameter, not inferred
 * from tracked tasks or an external calendar. No changes occur here.
 */
export type PlanningPriority = WorkPriority;
export type PlanningStatus = WorkStatus;
export type PlanningWork = {
  id: string;
  title: string;
  revision: number;
  status: PlanningStatus;
  priority: PlanningPriority;
  assigneeUserId: string | null;
  dueAt: Date | null;
  updatedAt: Date;
  findingSeverity: string;
  findingTitle: string;
  remediationStatus: string;
};
export type PlanningMember = {
  userId: string;
  name: string;
  role: string;
  email: string;
};
export type PlanningSetting = {
  userId: string;
  capacityPoints: number;
  available: boolean;
};
export type PlanningOptions = {
  horizonDays: 7 | 14 | 30 | 60 | 90;
  scope: "UNASSIGNED" | "ALL_OPEN";
  capacityPoints: number;
  settings: PlanningSetting[];
  includeBlocked: boolean;
  maxMoves: number;
  preserveOwners: boolean;
};
export type PlanningAllocation = {
  workId: string;
  title: string;
  revision: number;
  priority: PlanningPriority;
  dueAt: string | null;
  findingSeverity: string;
  fromUserId: string | null;
  proposedUserId: string | null;
  points: number;
  action: "ASSIGN" | "REASSIGN" | "KEEP" | "UNPLACED";
  reason: string;
};
export type PlanningMemberLoad = {
  userId: string;
  name: string;
  role: string;
  capacityPoints: number;
  existingPoints: number;
  plannedPoints: number;
  availablePoints: number;
  available: boolean;
  existingItems: number;
  plannedItems: number;
  overdueItems: number;
  urgentItems: number;
  utilizationPercent: number | null;
};
export type PlanningResult = {
  generatedAt: string;
  cutoff: string;
  parameters: PlanningOptions;
  totalOpenWork: number;
  considered: number;
  proposedMoves: number;
  unplaced: number;
  excluded: number;
  members: PlanningMemberLoad[];
  allocations: PlanningAllocation[];
  notes: string[];
  coverage: {
    totalFetched: number;
    truncated: boolean;
    reason: string;
  };
};
export type PlanningDataset = {
  items: PlanningWork[];
  members: PlanningMember[];
  truncated: boolean;
};

const DAY = 86400000;
const DEFAULT_CAPACITY = 20;
const MAX_CAPACITY = 1000;
const MAX_MOVES = 50;
const FETCH_BOUND = 2000;
const horizonValues = [7,14,30,60,90] as const;
const openStatuses = new Set<PlanningStatus>(["TODO","IN_PROGRESS","BLOCKED"]);
const priorityWeight: Record<PlanningPriority,number> = {
  LOW: 1, NORMAL: 2, HIGH: 4, URGENT: 6,
};
const severityWeight: Record<string,number> = {
  INFO: 0, LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3,
};
function isRecord(value: unknown): value is Record<string,unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function numeric(value: unknown, min: number, max: number, fallback: number) {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", `Expected an integer from ${min} to ${max}.`);
  return value;
}
function keys(value: Record<string,unknown>, allowed: readonly string[]) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key))
      throw new WorkInputError("INVALID", `Unknown planning option: ${key}.`);
  }
}
export function parsePlanningOptions(raw: unknown): PlanningOptions {
  if (!isRecord(raw))
    throw new WorkInputError("INVALID", "Planning request must be an object.");
  keys(raw, [
    "horizonDays","scope","capacityPoints","settings",
    "includeBlocked","maxMoves","preserveOwners",
  ]);
  const horizonDays = numeric(raw.horizonDays,7,90,30);
  if (!horizonValues.some(day => day === horizonDays))
    throw new WorkInputError("INVALID", "Unsupported planning horizon.");
  const scope = raw.scope === undefined ? "UNASSIGNED" : raw.scope;
  if (scope !== "UNASSIGNED" && scope !== "ALL_OPEN")
    throw new WorkInputError("INVALID", "Unknown planning scope.");
  const includeBlocked = raw.includeBlocked === undefined ? false : raw.includeBlocked;
  const preserveOwners = raw.preserveOwners === undefined ? true : raw.preserveOwners;
  if (typeof includeBlocked !== "boolean" || typeof preserveOwners !== "boolean")
    throw new WorkInputError("INVALID", "Planning toggles must be boolean.");
  const capacityPoints = numeric(raw.capacityPoints,0,MAX_CAPACITY,DEFAULT_CAPACITY);
  const maxMoves = numeric(raw.maxMoves,1,MAX_MOVES,MAX_MOVES);
  const settingsRaw = raw.settings ?? [];
  if (!Array.isArray(settingsRaw) || settingsRaw.length > 500)
    throw new WorkInputError("INVALID", "Too many per-member settings.");
  const seen = new Set<string>();
  const settings: PlanningSetting[] = settingsRaw.map(value => {
    if (!isRecord(value))
      throw new WorkInputError("INVALID", "Each member setting must be an object.");
    keys(value,["userId","capacityPoints","available"]);
    if (typeof value.userId !== "string" || !/^[a-zA-Z0-9_-]{5,100}$/.test(value.userId))
      throw new WorkInputError("INVALID", "Invalid planning member identifier.");
    if (seen.has(value.userId))
      throw new WorkInputError("INVALID", "Repeated member in planning settings.");
    seen.add(value.userId);
    if (typeof value.available !== "boolean")
      throw new WorkInputError("INVALID", "Member availability must be boolean.");
    return {
      userId:value.userId,
      capacityPoints:numeric(value.capacityPoints,0,MAX_CAPACITY,capacityPoints),
      available:value.available,
    };
  });
  return {
    horizonDays:horizonDays as PlanningOptions["horizonDays"],
    scope,capacityPoints,settings,includeBlocked,maxMoves,preserveOwners,
  };
}
export function workPoints(item: PlanningWork): number {
  return priorityWeight[item.priority] + (severityWeight[item.findingSeverity] ?? 1);
}
export function isOpen(item: PlanningWork) {
  return openStatuses.has(item.status);
}
export function isDueWithin(item: PlanningWork, cutoff: Date) {
  return item.dueAt === null || item.dueAt.getTime() <= cutoff.getTime();
}
export function planningScore(item: PlanningWork, now: Date) {
  let score = workPoints(item) * 100;
  if (item.dueAt) {
    const days = (item.dueAt.getTime()-now.getTime())/DAY;
    if (days < 0) score += 250 + Math.min(100,Math.floor(-days)*5);
    else if (days <= 7) score += 150 - Math.floor(days)*10;
    else if (days <= 30) score += 40;
  } else score += 15;
  if (item.status === "BLOCKED") score -= 75;
  if (item.status === "IN_PROGRESS") score += 25;
  return score;
}
export function comparePlanningWork(a: PlanningWork, b: PlanningWork, now: Date) {
  const left = planningScore(a,now), right = planningScore(b,now);
  if (left !== right) return right-left;
  const aTime = a.dueAt?.getTime() ?? Infinity;
  const bTime = b.dueAt?.getTime() ?? Infinity;
  return aTime-bTime || a.id.localeCompare(b.id);
}
function percentage(load:number,capacity:number):number|null {
  if (!capacity) return null;
  return Math.round(load/capacity*100);
}
function loadMember(
  person: PlanningMember,
  capacityPoints: number,
  available: boolean,
  work: readonly PlanningWork[],
  now: Date,
): PlanningMemberLoad {
  const current = work.filter(item => isOpen(item) && item.assigneeUserId === person.userId);
  const existingPoints = current.reduce((sum,item) => sum+workPoints(item),0);
  return {
    userId:person.userId,name:person.name,role:person.role,
    capacityPoints,available,existingPoints,plannedPoints:existingPoints,
    availablePoints:Math.max(0,capacityPoints-existingPoints),
    existingItems:current.length,plannedItems:current.length,
    overdueItems:current.filter(item => item.dueAt !== null &&
      item.dueAt.getTime()<now.getTime()).length,
    urgentItems:current.filter(item => item.priority === "URGENT").length,
    utilizationPercent:percentage(existingPoints,capacityPoints),
  };
}
export function planAssignments(
  dataset: PlanningDataset,
  options: PlanningOptions,
  now = new Date(),
): PlanningResult {
  const cutoff = new Date(now.getTime()+options.horizonDays*DAY);
  const members = dataset.members.map(person => {
    const setting = options.settings.find(entry => entry.userId === person.userId);
    return loadMember(
      person,setting?.capacityPoints ?? options.capacityPoints,
      setting?.available ?? true,dataset.items,now,
    );
  }).sort((a,b)=>a.name.localeCompare(b.name)||a.userId.localeCompare(b.userId));
  const knownMembers = new Set(members.map(person=>person.userId));
  const invalidSetting = options.settings.find(entry => !knownMembers.has(entry.userId));
  if (invalidSetting)
    throw new WorkInputError("INVALID", "Planning settings reference a non-member.");
  const allOpen = dataset.items.filter(isOpen);
  const candidate = allOpen.filter(item =>
    (options.includeBlocked || item.status !== "BLOCKED") &&
    isDueWithin(item,cutoff) &&
    (options.scope === "ALL_OPEN" || item.assigneeUserId === null),
  ).sort((a,b)=>comparePlanningWork(a,b,now));
  const allocations: PlanningAllocation[] = [];
  let moves = 0;
  for (const item of candidate) {
    const points = workPoints(item);
    const existing = members.find(person=>person.userId===item.assigneeUserId);
    let chosen: PlanningMemberLoad | undefined;
    let reason = "";
    if (existing && options.preserveOwners) {
      chosen=existing;
      reason="Existing owner retained by scenario policy.";
    } else {
      const eligible = members.filter(person => person.available &&
        person.capacityPoints > 0 &&
        person.plannedPoints + points <= person.capacityPoints);
      eligible.sort((a,b)=>{
        const aRatio=a.plannedPoints/a.capacityPoints;
        const bRatio=b.plannedPoints/b.capacityPoints;
        return aRatio-bRatio || a.plannedPoints-b.plannedPoints ||
          a.name.localeCompare(b.name)||a.userId.localeCompare(b.userId);
      });
      chosen=eligible[0];
      reason=chosen
        ? "Selected among members with sufficient scenario capacity."
        : "No available member has enough remaining scenario capacity.";
    }
    let action: PlanningAllocation["action"];
    if (existing && chosen?.userId===existing.userId) action="KEEP";
    else if (!chosen) action=existing?"KEEP":"UNPLACED";
    else if (moves>=options.maxMoves) {
      chosen=existing;
      action=existing?"KEEP":"UNPLACED";
      reason="Scenario reached maximum proposed moves.";
    } else {
      action=existing?"REASSIGN":"ASSIGN";
      moves++;
      chosen.plannedPoints+=points;
      chosen.plannedItems++;
      if (existing) {
        existing.plannedPoints-=points;
        existing.plannedItems--;
      }
    }
    allocations.push({
      workId:item.id,title:item.title,revision:item.revision,
      priority:item.priority,
      dueAt:item.dueAt?.toISOString()??null,
      findingSeverity:item.findingSeverity,
      fromUserId:item.assigneeUserId,
      proposedUserId:chosen?.userId??item.assigneeUserId,
      points,action,reason,
    });
  }
  for (const member of members) {
    member.availablePoints=Math.max(0,member.capacityPoints-member.plannedPoints);
    member.utilizationPercent=percentage(member.plannedPoints,member.capacityPoints);
  }
  return {
    generatedAt:now.toISOString(),
    cutoff:cutoff.toISOString(),
    parameters:options,totalOpenWork:allOpen.length,considered:candidate.length,
    proposedMoves:moves,
    unplaced:allocations.filter(row=>row.action==="UNPLACED").length,
    excluded:allOpen.length-candidate.length,
    members,allocations,
    notes:[
      "Capacity points are user-selected scenario units, not measured working hours.",
      "Suggested assignments do not execute work or alter verification state.",
      "Blocked tasks may require resolving dependencies before reassignment.",
      "Results are based on a bounded snapshot and may become stale before application.",
      "Apply through the reviewed, revision-checked work batch endpoint.",
    ],
    coverage:{
      totalFetched:dataset.items.length,truncated:dataset.truncated,
      reason:dataset.truncated
        ? "More than 2,000 work records exist; planning is partial and cannot be applied."
        : "All organization work records were available within the 2,000-record planning bound.",
    },
  };
}
export async function loadPlanningDataset(context:WorkContext):Promise<PlanningDataset>{
  if (!canManageWork(context.role))
    throw new WorkInputError("FORBIDDEN", "Planning assignment requires owner or admin.");
  const [rows,members]=await db.$transaction([
    db.remediationWorkItem.findMany({
      where:{organizationId:context.organizationId},
      select:{
        id:true,title:true,revision:true,status:true,priority:true,
        assigneeUserId:true,dueAt:true,updatedAt:true,
        finding:{select:{severity:true,title:true}},
        remediation:{select:{status:true}},
      },
      orderBy:[{id:"asc"}],take:FETCH_BOUND+1,
    }),
    db.membership.findMany({
      where:{organizationId:context.organizationId},
      select:{role:true,user:{select:{id:true,name:true,email:true}}},
      take:500,orderBy:{user:{name:"asc"}},
    }),
  ]);
  return {
    truncated:rows.length>FETCH_BOUND,
    items:rows.slice(0,FETCH_BOUND).map(row=>({
      id:row.id,title:row.title,revision:row.revision,
      status:row.status,priority:row.priority,
      assigneeUserId:row.assigneeUserId,dueAt:row.dueAt,
      updatedAt:row.updatedAt,
      findingSeverity:row.finding.severity,
      findingTitle:row.finding.title,
      remediationStatus:row.remediation.status,
    })),
    members:members.map(member=>({
      userId:member.user.id,name:member.user.name,email:member.user.email,role:member.role,
    })),
  };
}
export async function buildPlanningScenario(
  context:WorkContext,raw:unknown,now=new Date(),
):Promise<PlanningResult>{
  const options=parsePlanningOptions(raw);
  const dataset=await loadPlanningDataset(context);
  return planAssignments(dataset,options,now);
}
