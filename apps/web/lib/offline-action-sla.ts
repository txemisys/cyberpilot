import {createHash} from "node:crypto";
import type{ActionSnapshot,ActionState,ActionPriority,
  ActionDomainEvent}from "./integrated-action-domain";
import {validateActionSnapshot}from "./integrated-action-domain";

export type CalendarDay=0|1|2|3|4|5|6;
export type SlaRule={
  id:string;priority:ActionPriority;
  firstResponseBusinessHours:number;
  completionBusinessHours:number;
  warningBusinessHours:number;
  escalationBusinessHours:number;
  appliesToStates:ActionState[];
};
export type SlaCalendar={
  timezoneOffsetMinutes:number;
  workingDays:CalendarDay[];
  startHour:number;endHour:number;
  excludedDates:string[];
};
export type SlaInput={
  organizationId:string;asOf:string;
  actions:ActionSnapshot[];
  events:ActionDomainEvent[];
  calendar:SlaCalendar;rules:SlaRule[];
  actionLimit:number;eventLimit:number;
  truncatedActions:boolean;truncatedEvents:boolean;
};
export type SlaSignalCode=
  "NO_OWNER"|"NO_DUE_DATE"|"RESPONSE_OVERDUE"|
  "COMPLETION_OVERDUE"|"RESPONSE_WARNING"|
  "COMPLETION_WARNING"|"STALE_PROGRESS"|
  "BLOCKER_ESCALATION"|"EXCEPTION_EXPIRING"|
  "EXCEPTION_EXPIRED"|"EVIDENCE_UNLINKED"|
  "AUDIT_INCOMPLETE"|"AUDIT_CONFLICT"|
  "NO_APPROPRIATE_RULE"|"MANUAL_REVIEW";
export type SlaSignal={
  key:string;organizationId:string;actionId:string;
  ruleId:string|null;code:SlaSignalCode;
  level:"BLOCK"|"URGENT"|"WARNING"|"INFO";
  description:string;recommendedAction:string;
  priority:ActionPriority;status:ActionState;
  deadline:string|null;
  elapsedBusinessMinutes:number|null;
  allowedBusinessMinutes:number|null;
  overdueBusinessMinutes:number|null;
  ownerUserId:string|null;actorRefs:string[];
  dispatchQueued:false;externalMessageSent:false;
  remediationVerified:false;customerConsentInferred:false;
};
export type SlaActionRow={
  organizationId:string;actionId:string;
  riskKey:string;title:string;
  ownerUserId:string|null;priority:ActionPriority;
  status:ActionState;revision:number;
  responseDeadline:string|null;
  completionDeadline:string|null;
  dueAt:string|null;exceptionExpiresAt:string|null;
  firstTransitionAt:string|null;
  lastActivityAt:string;
  elapsedBusinessMinutes:number;
  expectedBusinessMinutes:number|null;
  signalKeys:string[];
  worstLevel:SlaSignal["level"]|"NONE";
  resolvedInProvider:false;
  businessApprovalConfirmed:false;
};
export type SlaOwnerWorkload={
  ownerUserId:string|null;total:number;
  urgent:number;blocked:number;overdue:number;
  noDueDate:number;reportedDone:number;
  exceptions:number;oldestActivity:string|null;
  independentlyVerifiedCompleted:0;
};
export type SlaOperationalReport={
  schema:"cyberpilot.offline.sla.v1";
  organizationId:string;asOf:string;
  window:{
    timezoneOffsetMinutes:number;
    businessWeekDays:CalendarDay[];
    openingHour:number;closingHour:number;
    holidaysIgnored:false;
    exclusions:string[];
  };
  state:"REVIEW_REQUIRED"|"INCOMPLETE"|"NO_TRACKED_ACTIONS";
  rows:SlaActionRow[];
  signals:SlaSignal[];workloads:SlaOwnerWorkload[];
  overview:{
    totalActions:number;unowned:number;dueMissing:number;
    responseOverdue:number;completionOverdue:number;
    escalations:number;blocked:number;
    exceptionsExpired:number;exceptionsExpiring:number;
    noEvidence:number;auditDefects:number;
    sourceTruncated:boolean;
    dispatches:0;externalProviderCalls:0;
    verifiedRemediations:0;
  };
  issues:string[];
  policyRequiresOperatorApproval:true;
  noRealTenantActions:true;
  providerAutomationDisabled:true;
  externalNotificationsDispatched:false;
  historicalCyberScoreTouched:false;
  reportDigest:string;
};
export type SlaFilter={
  levels?:SlaSignal["level"][];
  codes?:SlaSignalCode[];
  ownerUserId?:string|null;
  priority?:ActionPriority[];
  state?:ActionState[];
  includeWarnings?:boolean;
  search?:string;
};
const priorities:ActionPriority[]=["URGENT","HIGH","NORMAL","LOW"];
const levels:SlaSignal["level"][]=["BLOCK","URGENT","WARNING","INFO"];
const codes:readonly SlaSignalCode[]=[
  "NO_OWNER","NO_DUE_DATE","RESPONSE_OVERDUE",
  "COMPLETION_OVERDUE","RESPONSE_WARNING","COMPLETION_WARNING",
  "STALE_PROGRESS","BLOCKER_ESCALATION","EXCEPTION_EXPIRING",
  "EXCEPTION_EXPIRED","EVIDENCE_UNLINKED","AUDIT_INCOMPLETE",
  "AUDIT_CONFLICT","NO_APPROPRIATE_RULE","MANUAL_REVIEW",
];
const iso=(x:string)=>typeof x==="string"&&
  Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
const utcDay=(x:string)=>/^\d{4}-\d\d-\d\d$/.test(x)&&
  Number.isFinite(Date.parse(x+"T00:00:00Z"))&&
  new Date(x+"T00:00:00Z").toISOString().slice(0,10)===x;
const sha=(s:string)=>createHash("sha256").update(s).digest("hex");
function canonical(x:unknown):string{
  if(x===null||typeof x==="string"||typeof x==="boolean"||
    typeof x==="number"){
    if(typeof x==="number"&&!Number.isFinite(x))
      throw Error("SLA_NONFINITE");
    return JSON.stringify(x);
  }
  if(Array.isArray(x))return"["+x.map(canonical).join(",")+"]";
  if(typeof x==="object")return"{"+Object.entries(x)
    .sort(([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
  throw Error("SLA_NONCANONICAL");
}
const digest=(x:unknown)=>sha(canonical(x));
const unique=<T>(values:readonly T[]):T[]=>[...new Set(values)];
export function defaultSlaRules():SlaRule[]{
  return[
    {id:"urgent",priority:"URGENT",
      firstResponseBusinessHours:2,completionBusinessHours:16,
      warningBusinessHours:2,escalationBusinessHours:2,
      appliesToStates:["OPEN","IN_PROGRESS","BLOCKED","REOPENED"]},
    {id:"high",priority:"HIGH",
      firstResponseBusinessHours:4,completionBusinessHours:40,
      warningBusinessHours:8,escalationBusinessHours:8,
      appliesToStates:["OPEN","IN_PROGRESS","BLOCKED","REOPENED"]},
    {id:"normal",priority:"NORMAL",
      firstResponseBusinessHours:16,completionBusinessHours:80,
      warningBusinessHours:16,escalationBusinessHours:16,
      appliesToStates:["OPEN","IN_PROGRESS","BLOCKED","REOPENED"]},
    {id:"low",priority:"LOW",
      firstResponseBusinessHours:40,completionBusinessHours:160,
      warningBusinessHours:40,escalationBusinessHours:40,
      appliesToStates:["OPEN","IN_PROGRESS","BLOCKED","REOPENED"]},
  ];
}
export function defaultSlaCalendar():SlaCalendar{
  return{
    timezoneOffsetMinutes:60,workingDays:[1,2,3,4,5],
    startHour:9,endHour:17,excludedDates:[],
  };
}
export function validateSlaPolicy(
  calendar:SlaCalendar,rules:SlaRule[]):string[]{
  const issues:string[]=[];
  if(!Number.isInteger(calendar.timezoneOffsetMinutes)||
    Math.abs(calendar.timezoneOffsetMinutes)>840)
    issues.push("TIMEZONE_INVALID");
  if(!Number.isInteger(calendar.startHour)||
    !Number.isInteger(calendar.endHour)||
    calendar.startHour<0||calendar.endHour>24||
    calendar.endHour<=calendar.startHour)
    issues.push("BUSINESS_HOURS_INVALID");
  if(!Array.isArray(calendar.workingDays)||
    calendar.workingDays.length<1||
    new Set(calendar.workingDays).size!==calendar.workingDays.length||
    calendar.workingDays.some(x=>!Number.isInteger(x)||x<0||x>6))
    issues.push("WORK_DAYS_INVALID");
  if(!Array.isArray(calendar.excludedDates)||
    calendar.excludedDates.length>500||
    new Set(calendar.excludedDates).size!==calendar.excludedDates.length||
    calendar.excludedDates.some(x=>!utcDay(x)))
    issues.push("EXCLUDED_DATES_INVALID");
  if(!Array.isArray(rules)||rules.length<1||rules.length>50)
    issues.push("RULE_COUNT_INVALID");
  if(new Set(rules.map(x=>x.id)).size!==rules.length)
    issues.push("RULE_ID_CONFLICT");
  if(new Set(rules.map(x=>x.priority)).size!==rules.length)
    issues.push("PRIORITY_RULE_CONFLICT");
  for(const rule of rules){
    if(!/^[a-z0-9_-]{2,60}$/.test(rule.id)||
      !priorities.includes(rule.priority)||
      !Number.isFinite(rule.firstResponseBusinessHours)||
      !Number.isFinite(rule.completionBusinessHours)||
      !Number.isFinite(rule.warningBusinessHours)||
      !Number.isFinite(rule.escalationBusinessHours)||
      rule.firstResponseBusinessHours<=0||
      rule.completionBusinessHours<rule.firstResponseBusinessHours||
      rule.completionBusinessHours>10000||
      rule.warningBusinessHours<0||
      rule.escalationBusinessHours<0||
      !Array.isArray(rule.appliesToStates)||
      rule.appliesToStates.length<1||
      new Set(rule.appliesToStates).size!==rule.appliesToStates.length)
      issues.push("RULE_INVALID:"+rule.id);
  }
  return unique(issues);
}
function localDate(ms:number,offset:number){
  return new Date(ms+offset*60000);
}
function localDay(ms:number,offset:number){
  return localDate(ms,offset).toISOString().slice(0,10);
}
function isWorkingMinute(ms:number,calendar:SlaCalendar){
  const local=localDate(ms,calendar.timezoneOffsetMinutes);
  const day=local.getUTCDay() as CalendarDay;
  const hour=local.getUTCHours();
  return calendar.workingDays.includes(day)&&
    !calendar.excludedDates.includes(localDay(ms,calendar.timezoneOffsetMinutes))&&
    hour>=calendar.startHour&&hour<calendar.endHour;
}
/** Work minute iterator: UTC-safe, deterministic, bounds checked. */
export function businessMinutesBetween(
  start:string,end:string,calendar:SlaCalendar):number{
  if(!iso(start)||!iso(end)||start>end)
    throw Error("INVALID_BUSINESS_INTERVAL");
  const minutes=(Date.parse(end)-Date.parse(start))/60000;
  if(minutes>366*24*60)
    throw Error("SLA_WINDOW_TOO_LARGE");
  const startMs=Math.floor(Date.parse(start)/60000)*60000;
  const endMs=Date.parse(end);
  let total=0;
  for(let ms=startMs;ms<endMs;ms+=60000){
    if(!isWorkingMinute(ms,calendar))continue;
    const left=Math.max(ms,Date.parse(start));
    const right=Math.min(ms+60000,endMs);
    total+=Math.max(0,right-left)/60000;
  }
  return Math.round(total*1000)/1000;
}
/** Avoid unbounded loops and drift across UTC day boundaries. */
export function addBusinessMinutes(
  from:string,amount:number,calendar:SlaCalendar):string{
  if(!iso(from)||!Number.isSafeInteger(amount)||
    amount<0||amount>600000)
    throw Error("INVALID_BUSINESS_DEADLINE");
  if(amount===0)return from;
  const current=Date.parse(from);
  let remaining=amount;
  let ms=Math.ceil(current/60000)*60000;
  const end=current+Math.max(365*86400000,
    amount*10*60000);
  while(ms<end){
    if(isWorkingMinute(ms,calendar)){
      remaining--;
      if(remaining===0)return new Date(ms+60000).toISOString();
    }
    ms+=60000;
  }
  throw Error("SLA_DEADLINE_OUT_OF_RANGE");
}
function minutesUntil(reference:string,deadline:string,
 calendar:SlaCalendar){
  if(reference<=deadline)
    return businessMinutesBetween(reference,deadline,calendar);
  return -businessMinutesBetween(deadline,reference,calendar);
}
function signal(action:ActionSnapshot,code:SlaSignalCode,
  level:SlaSignal["level"],at:string,
  rule:SlaRule|null,deadline:string|null,
  calendar:SlaCalendar,reason:string,
  eventActors:string[]=[]):SlaSignal{
  const left=deadline?minutesUntil(at,deadline,calendar):null;
  return{
    key:digest([action.organizationId,action.actionId,code,
      rule?.id??"NO_RULE"]),
    organizationId:action.organizationId,
    actionId:action.actionId,
    ruleId:rule?.id??null,code,level,
    description:reason,
    recommendedAction:
      code==="NO_OWNER"?"Assign an eligible local member before due date.":
      code==="NO_DUE_DATE"?"Set an explicit internal action due date.":
      code==="RESPONSE_OVERDUE"||code==="COMPLETION_OVERDUE"?
        "Escalate to an authorized organization manager for review.":
      code==="EXCEPTION_EXPIRED"?
        "Reopen expired exception and reassess the reported exposure.":
      code==="AUDIT_INCOMPLETE"||code==="AUDIT_CONFLICT"?
        "Reconcile immutable CAS events before trusting workflow claims.":
        "Review locally, record actor and evidence; do not mark security verified.",
    priority:action.priority,status:action.status,
    deadline,elapsedBusinessMinutes:left===null?null:-left,
    allowedBusinessMinutes:rule?
      rule.completionBusinessHours*60:null,
    overdueBusinessMinutes:left===null?null:
      Math.max(0,-left),ownerUserId:action.ownerUserId,
    actorRefs:unique(eventActors).sort(),
    dispatchQueued:false,externalMessageSent:false,
    remediationVerified:false,customerConsentInferred:false,
  };
}
function ruleFor(action:ActionSnapshot,rules:SlaRule[]){
  return rules.find(x=>x.priority===action.priority&&
    x.appliesToStates.includes(action.status))??null;
}
function actionEvents(action:ActionSnapshot,events:ActionDomainEvent[]){
  return events.filter(x=>x.actionId===action.actionId&&
    x.organizationId===action.organizationId)
    .sort((a,b)=>a.revision-b.revision);
}
function evaluateAction(action:ActionSnapshot,at:string,
  rules:SlaRule[],calendar:SlaCalendar,
  events:ActionDomainEvent[]):{
    row:SlaActionRow;signals:SlaSignal[];issues:string[];
  }{
  const signals:SlaSignal[]=[];
  const issues:string[]=[];
  const relevant=actionEvents(action,events);
  const rule=ruleFor(action,rules);
  const active=["OPEN","IN_PROGRESS","BLOCKED","REOPENED"]
    .includes(action.status);
  const baseline=relevant[0]?.occurredAt??action.updatedAt;
  const response=relevant.find(x=>x.kind!=="CREATE");
  const responseAt=response?.occurredAt??null;
  const responseDeadline=rule?
    addBusinessMinutes(baseline,
      rule.firstResponseBusinessHours*60,calendar):null;
  const completionDeadline=rule?
    addBusinessMinutes(baseline,
      rule.completionBusinessHours*60,calendar):null;
  const latest=relevant.at(-1)?.occurredAt??action.updatedAt;
  const actorRefs=relevant.map(x=>x.actorUserId);
  const put=(code:SlaSignalCode,level:SlaSignal["level"],
    deadline:string|null,reason:string)=>
    signals.push(signal(action,code,level,at,rule,deadline,
      calendar,reason,actorRefs));
  if(!validateActionSnapshot(action).valid){
    issues.push("INVALID_ACTION:"+action.actionId);
    put("AUDIT_CONFLICT","BLOCK",null,
      "Action snapshot fails the invariant validator.");
  }
  if(relevant.length!==action.revision||
    relevant.some((x,i)=>x.revision!==i+1)){
    issues.push("AUDIT_GAP:"+action.actionId);
    put("AUDIT_INCOMPLETE","BLOCK",null,
      "Immutable action events do not form a contiguous revision chain.");
  }
  if(!rule&&active)
    put("NO_APPROPRIATE_RULE","WARNING",null,
      "No locally configured SLA applies to this state and priority.");
  if(active&&!action.ownerUserId)
    put("NO_OWNER","URGENT",null,
      "Action has no accountable tenant member assigned.");
  if(active&&!action.dueAt)
    put("NO_DUE_DATE","WARNING",null,
      "No operator-defined due date exists for this action.");
  if(action.evidenceRefs.length===0)
    put("EVIDENCE_UNLINKED","WARNING",null,
      "Action has no source evidence identifiers.");
  if(active&&rule&&responseDeadline&&!responseAt){
    const remaining=minutesUntil(at,responseDeadline,calendar);
    if(remaining<0)put("RESPONSE_OVERDUE","URGENT",
      responseDeadline,"First human response exceeded internal business-hour SLA.");
    else if(remaining<=rule.warningBusinessHours*60)
      put("RESPONSE_WARNING","WARNING",responseDeadline,
        "First response approaching internal target.");
  }
  if(active&&rule&&completionDeadline){
    const deadline=action.dueAt&&action.dueAt<completionDeadline?
      action.dueAt:completionDeadline;
    const remaining=minutesUntil(at,deadline,calendar);
    if(remaining<0)put("COMPLETION_OVERDUE","URGENT",
      deadline,"Unverified action has exceeded internal completion target.");
    else if(remaining<=rule.warningBusinessHours*60)
      put("COMPLETION_WARNING","WARNING",
        deadline,"Completion target is approaching; review scope and owner.");
    const stale=businessMinutesBetween(
      latest<=at?latest:at,at,calendar);
    if(stale>rule.escalationBusinessHours*60)
      put("STALE_PROGRESS","WARNING",null,
        "No audited progress event within configured escalation interval.");
  }
  if(action.status==="BLOCKED"&&rule){
    const stale=businessMinutesBetween(latest<=at?latest:at,
      at,calendar);
    if(stale>rule.escalationBusinessHours*60)
      put("BLOCKER_ESCALATION","URGENT",null,
        "Blocker remains without a recent audited update.");
  }
  if(action.status==="EXCEPTION"&&action.exceptionExpiresAt){
    const ms=Date.parse(action.exceptionExpiresAt)-Date.parse(at);
    if(ms<=0)
      put("EXCEPTION_EXPIRED","URGENT",action.exceptionExpiresAt,
        "Exception is past its recorded local expiry.");
    else if(ms<=7*86400000)
      put("EXCEPTION_EXPIRING","WARNING",action.exceptionExpiresAt,
        "Exception expires within seven calendar days.");
  }
  if(action.status==="DONE_REPORTED")
    put("MANUAL_REVIEW","INFO",null,
      "Completion is operator-reported, not independently verified.");
  if(action.status==="REOPENED")
    put("MANUAL_REVIEW","INFO",null,
      "Reopened work must be reassessed against present source evidence.");
  const level:Record<SlaSignal["level"],number>={
    BLOCK:0,URGENT:1,WARNING:2,INFO:3,
  };
  const worst=signals.length?
    signals.reduce((a,b)=>level[a.level]<=level[b.level]?a:b).level:
    "NONE" as const;
  return{
    row:{
      organizationId:action.organizationId,actionId:action.actionId,
      riskKey:action.riskKey,title:action.title,
      ownerUserId:action.ownerUserId,priority:action.priority,
      status:action.status,revision:action.revision,
      responseDeadline,completionDeadline,dueAt:action.dueAt,
      exceptionExpiresAt:action.exceptionExpiresAt,
      firstTransitionAt:responseAt,lastActivityAt:latest,
      elapsedBusinessMinutes:businessMinutesBetween(
        baseline<=at?baseline:at,at,calendar),
      expectedBusinessMinutes:rule?rule.completionBusinessHours*60:null,
      signalKeys:signals.map(x=>x.key),worstLevel:worst,
      resolvedInProvider:false,businessApprovalConfirmed:false,
    },
    signals,issues,
  };
}
function owners(actions:ActionSnapshot[],
  signals:SlaSignal[]):SlaOwnerWorkload[]{
  const list=unique(actions.map(x=>x.ownerUserId)).sort(
    (a,b)=>(a??"").localeCompare(b??""));
  return list.map(ownerUserId=>{
    const items=actions.filter(x=>x.ownerUserId===ownerUserId);
    const relevant=signals.filter(x=>x.ownerUserId===ownerUserId);
    return{
      ownerUserId,total:items.length,
      urgent:relevant.filter(x=>x.level==="URGENT").length,
      blocked:items.filter(x=>x.status==="BLOCKED").length,
      overdue:unique(relevant.filter(x=>["RESPONSE_OVERDUE",
        "COMPLETION_OVERDUE"].includes(x.code)).map(x=>x.actionId)).length,
      noDueDate:items.filter(x=>x.dueAt===null).length,
      reportedDone:items.filter(x=>x.status==="DONE_REPORTED").length,
      exceptions:items.filter(x=>x.status==="EXCEPTION").length,
      oldestActivity:items.map(x=>x.updatedAt).sort()[0]??null,
      independentlyVerifiedCompleted:0,
    };
  });
}
export function buildSlaOperationalReport(input:SlaInput):
  SlaOperationalReport{
  if(!iso(input.asOf)||!input.organizationId||
    validateSlaPolicy(input.calendar,input.rules).length)
    throw Error("INVALID_TENANT_OR_POLICY");
  if(input.actions.length>500||input.events.length>2500)
    throw Error("SLA_INPUT_EXCEEDS_SAFE_BOUND");
  const issues:string[]=[];
  if(input.actions.some(x=>x.organizationId!==input.organizationId)||
    input.events.some(x=>x.organizationId!==input.organizationId))
    throw Error("CROSS_TENANT_SLA_SOURCE");
  if(input.truncatedActions||input.truncatedEvents)
    issues.push("SLA_SOURCE_TRUNCATED");
  if(input.actions.length!==new Set(input.actions.map(x=>x.actionId)).size)
    throw Error("DUPLICATE_ACTION_ID");
  const evaluated=input.actions.map(action=>evaluateAction(
    action,input.asOf,input.rules,input.calendar,input.events));
  issues.push(...evaluated.flatMap(x=>x.issues));
  const rows=evaluated.map(x=>x.row);
  const signals=evaluated.flatMap(x=>x.signals).sort((a,b)=>
    levels.indexOf(a.level)-levels.indexOf(b.level)||
      a.actionId.localeCompare(b.actionId)||
      a.code.localeCompare(b.code));
  if(signals.length!==new Set(signals.map(x=>x.key)).size)
    throw Error("SLA_SIGNAL_COLLISION");
  const count=(code:SlaSignalCode)=>signals.filter(x=>x.code===code).length;
  const overview={
    totalActions:rows.length,
    unowned:rows.filter(x=>x.ownerUserId===null).length,
    dueMissing:rows.filter(x=>x.dueAt===null).length,
    responseOverdue:count("RESPONSE_OVERDUE"),
    completionOverdue:count("COMPLETION_OVERDUE"),
    escalations:count("BLOCKER_ESCALATION"),
    blocked:rows.filter(x=>x.status==="BLOCKED").length,
    exceptionsExpired:count("EXCEPTION_EXPIRED"),
    exceptionsExpiring:count("EXCEPTION_EXPIRING"),
    noEvidence:count("EVIDENCE_UNLINKED"),
    auditDefects:count("AUDIT_INCOMPLETE")+count("AUDIT_CONFLICT"),
    sourceTruncated:input.truncatedActions||input.truncatedEvents,
    dispatches:0 as const,externalProviderCalls:0 as const,
    verifiedRemediations:0 as const,
  };
  const base={
    schema:"cyberpilot.offline.sla.v1" as const,
    organizationId:input.organizationId,asOf:input.asOf,
    window:{
      timezoneOffsetMinutes:input.calendar.timezoneOffsetMinutes,
      businessWeekDays:[...input.calendar.workingDays],
      openingHour:input.calendar.startHour,
      closingHour:input.calendar.endHour,
      holidaysIgnored:false as const,
      exclusions:[...input.calendar.excludedDates],
    },
    state:(issues.length?"INCOMPLETE":
      rows.length===0?"NO_TRACKED_ACTIONS":"REVIEW_REQUIRED") as
      SlaOperationalReport["state"],
    rows,signals,workloads:owners(input.actions,signals),
    overview,issues:unique(issues),
    policyRequiresOperatorApproval:true as const,
    noRealTenantActions:true as const,
    providerAutomationDisabled:true as const,
    externalNotificationsDispatched:false as const,
    historicalCyberScoreTouched:false as const,
  };
  return{...base,reportDigest:digest(base)};
}
export function verifySlaOperationalReport(
  report:SlaOperationalReport,tenant?:string){
  const errors:string[]=[];
  const{reportDigest,...base}=report;
  if(digest(base)!==reportDigest)errors.push("SLA_DIGEST_MISMATCH");
  if(tenant&&tenant!==report.organizationId)errors.push("TENANT_MISMATCH");
  if(report.overview.externalProviderCalls!==0||
    report.overview.verifiedRemediations!==0||
    report.externalNotificationsDispatched!==false||
    report.providerAutomationDisabled!==true||
    report.historicalCyberScoreTouched!==false)
    errors.push("FALSE_SLA_AUTOMATION");
  if(report.rows.some(x=>x.resolvedInProvider!==false||
    x.businessApprovalConfirmed!==false||
    x.organizationId!==report.organizationId))
    errors.push("INVALID_ACTION_ASSERTION");
  if(report.signals.some(x=>x.externalMessageSent!==false||
    x.dispatchQueued!==false||x.remediationVerified!==false||
    x.customerConsentInferred!==false))
    errors.push("FALSE_SLA_SIGNAL_DISPATCH");
  return{valid:errors.length===0,errors};
}
export function filterSlaSignals(
  report:SlaOperationalReport,filter:SlaFilter={}){
  if(!verifySlaOperationalReport(report).valid)
    throw Error("INVALID_SLA_REPORT");
  const text=filter.search?.trim().toLowerCase()??"";
  return report.signals.filter(x=>
    (!filter.levels||filter.levels.includes(x.level))&&
    (!filter.codes||filter.codes.includes(x.code))&&
    (filter.ownerUserId===undefined||
      x.ownerUserId===filter.ownerUserId)&&
    (!filter.priority||filter.priority.includes(x.priority))&&
    (!filter.state||filter.state.includes(x.status))&&
    (filter.includeWarnings!==false||x.level!=="WARNING")&&
    (!text||[x.code,x.description,x.recommendedAction,
      x.actionId].join(" ").toLowerCase().includes(text)));
}
export function compareSlaReports(
  previous:SlaOperationalReport,current:SlaOperationalReport){
  if(!verifySlaOperationalReport(previous).valid||
    !verifySlaOperationalReport(current).valid||
    previous.organizationId!==current.organizationId||
    previous.asOf>=current.asOf)
    throw Error("INVALID_SLA_COMPARISON");
  const before=new Map(previous.signals.map(x=>[x.key,x]));
  const after=new Map(current.signals.map(x=>[x.key,x]));
  const appeared=current.signals.filter(x=>!before.has(x.key));
  const disappeared=previous.signals.filter(x=>!after.has(x.key));
  return{
    organizationId:current.organizationId,
    beforeDigest:previous.reportDigest,
    afterDigest:current.reportDigest,
    newlyDetected:appeared.map(x=>x.key),
    noLongerDetected:disappeared.map(x=>x.key),
    overdueDelta:current.overview.completionOverdue-
      previous.overview.completionOverdue,
    unownedDelta:current.overview.unowned-
      previous.overview.unowned,
    blockedDelta:current.overview.blocked-
      previous.overview.blocked,
    noLongerDetectedMeansRemediated:false as const,
    notificationsSent:false as const,
  };
}
export function exportSlaOperationalReport(
  report:SlaOperationalReport,
  format:"JSON"|"CSV"|"MARKDOWN"){
  if(!verifySlaOperationalReport(report).valid)
    throw Error("SLA_REPORT_INVALID_FOR_EXPORT");
  const stem="offline-sla-"+report.asOf.slice(0,10);
  if(format==="JSON")return{
    filename:stem+".json",mime:"application/json",
    content:JSON.stringify(report,null,2),
  };
  const q=(x:string|number|null)=>'"'+
    String(x??"").replaceAll('"','""')+'"';
  if(format==="CSV")return{
    filename:stem+".csv",mime:"text/csv",
    content:[
      "signalKey,actionId,code,level,priority,status,owner,deadline,description",
      ...report.signals.map(x=>[
        x.key,x.actionId,x.code,x.level,x.priority,
        x.status,x.ownerUserId,x.deadline,x.description,
      ].map(q).join(",")),
    ].join("\n"),
  };
  if(format!=="MARKDOWN")throw Error("INVALID_SLA_FORMAT");
  return{
    filename:stem+".md",mime:"text/markdown",
    content:[
      "# Internal action follow-up targets",
      "Organization: "+report.organizationId,
      "As of: "+report.asOf,"Status: "+report.state,
      "Integrity digest: "+report.reportDigest,"",
      ...report.signals.map(x=>
        "## "+x.level+" "+x.code+"\n"+
        "Action: "+x.actionId+"\n"+
        "Deadline: "+(x.deadline??"Not set")+"\n"+
        x.description+"\n"+x.recommendedAction+"\n"),
      "No automatic message was sent; no customer remediation was verified.",
    ].join("\n"),
  };
}
