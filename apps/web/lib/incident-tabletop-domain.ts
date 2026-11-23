import { createHash } from "node:crypto";
import { getIncidentPlaybook, INCIDENT_TYPES,
  type IncidentType, type IncidentStep } from "./incident-playbook-catalog";
export const TABLETOP_FAULTS = [
  "MISSING_TELEMETRY", "SOURCE_THROTTLING", "STALE_EVIDENCE",
  "PRIVILEGED_ACCOUNT", "UNKNOWN_DEVICE", "NO_MAILBOX_ACCESS",
  "PARTIAL_PROVIDER_RESULT", "CROSS_TENANT_REFERENCE",
  "APPROVAL_EXPIRED", "APPROVER_IS_REQUESTER",
  "DESTRUCTIVE_ACTION_REQUEST", "EXECUTOR_UNAVAILABLE",
  "INCOMPLETE_RECIPIENTS", "RANSOMWARE_SPREAD",
  "PAYMENT_CHANGE_PRESSURE", "LOSS_OF_BACKUPS",
  "MFA_RESET_PRESSURE", "INCOMPLETE_INVENTORY",
  "ALERT_FALSE_POSITIVE", "PROVIDER_SCOPE_MISMATCH",
] as const;
export type TabletopFault = typeof TABLETOP_FAULTS[number];
export type TabletopActorRole =
  "INCIDENT_COMMANDER" | "SECURITY_REVIEWER" | "IT_OPERATOR" |
  "FINANCE_APPROVER" | "LEGAL_REVIEWER" | "EVIDENCE_COLLECTOR";
export type TabletopDecision =
  "DECLARE_UNKNOWN" | "COLLECT_EVIDENCE" | "ESCALATE" |
  "REQUEST_INDEPENDENT_APPROVAL" | "MARK_PROVEN" |
  "SEND_PROVIDER_COMMAND" | "SKIP_STEP" | "REQUEST_MANUAL_VERIFICATION";
export type TabletopScenario = {
  schema: "cyberpilot.incident.tabletop.scenario.v1";
  id: string; organizationId: string; incidentType: IncidentType;
  title: string; createdAt: string; scenarioSeed: number;
  playbookDigest: string; injectedFaults: TabletopFault[];
  activeStepIds: string[]; startingState: "UNKNOWN";
  scriptedSignals: Array<{ id: string; fault: TabletopFault;
    source: string; state: "UNKNOWN" | "ERROR" | "DECLARED";
    trusted: false; message: string }>;
  injectedRisk: "P0" | "P1" | "P2";
  independentProviderEvidence: false;
  liveProviderCredential: false; tenantConsentForWrites: false;
};
export type TabletopMove = {
  id: string; stepId: string; actorRole: TabletopActorRole;
  command: TabletopDecision; reason: string; at: string;
  assertedIndependentEvidence: boolean;
  assertedExternalCompletion: boolean;
};
export type TabletopEvent = {
  revision: number; moveId: string; stepId: string; command: TabletopDecision;
  actorRole: TabletopActorRole; at: string; accepted: boolean;
  code: string; previousGate: string; nextGate: string;
  detailsDigest: string; providerWrites: 0;
  liveSecurityBenefitProven: false;
};
export type TabletopStepState = {
  stepId: string; state: "NOT_REVIEWED" | "UNKNOWN" | "ESCALATED" |
    "EVIDENCE_REQUESTED" | "APPROVAL_REQUESTED" | "READY_FOR_MANUAL_REVIEW";
  revision: number; touchedAt: string | null; lastActorRole: TabletopActorRole | null;
  evidenceRequested: boolean; manualVerificationRequested: boolean;
  escalated: boolean; independentApprovalRequested: boolean;
  sourceFaults: TabletopFault[]; actionsAttempted: number;
  unsupportedAssertionsRejected: number;
};
export type TabletopExercise = {
  schema: "cyberpilot.incident.tabletop.exercise.v1";
  organizationId: string; scenarioId: string; incidentType: IncidentType;
  scenarioDigest: string; revision: number; status: "RUNNING" | "REVIEWED";
  createdAt: string; updatedAt: string;
  steps: TabletopStepState[]; events: TabletopEvent[];
  acceptedMoves: number; rejectedMoves: number;
  unsafeOperationsBlocked: number; unknownsPreserved: number;
  externalProviderWrites: 0; operationalContainmentProven: false;
  exerciseDigest: string;
};
export type TabletopOutcome = {
  accepted: boolean; code: string; exercise: TabletopExercise;
  event: TabletopEvent | null; providerWrites: 0;
  realWorldRemediationVerified: false;
};
const validId = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const validTime = (x: unknown): x is string => typeof x === "string" &&
  Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const digest = (x: unknown) => createHash("sha256")
  .update(JSON.stringify(x)).digest("hex");
const stepFor = (type: IncidentType, id: string) =>
  getIncidentPlaybook(type).steps.find(step => step.id === id);
const FAULT_CLASS: Record<TabletopFault,
  {source: string; state: "UNKNOWN"|"ERROR"|"DECLARED"; message: string}> = {
  MISSING_TELEMETRY: {source:"provider-telemetry",state:"UNKNOWN",
    message:"Required telemetry is not available; do not interpret absence as no impact"},
  SOURCE_THROTTLING: {source:"provider-api",state:"ERROR",
    message:"Source is throttling or returning temporary failures"},
  STALE_EVIDENCE: {source:"evidence-observation",state:"UNKNOWN",
    message:"Evidence is older than the simulated incident window"},
  PRIVILEGED_ACCOUNT: {source:"identity-review",state:"DECLARED",
    message:"A privileged principal is reported at risk but not confirmed"},
  UNKNOWN_DEVICE: {source:"device-identity",state:"UNKNOWN",
    message:"Reported endpoint cannot be mapped to a verified managed device"},
  NO_MAILBOX_ACCESS: {source:"mailbox-inventory",state:"ERROR",
    message:"Mailbox permissions are insufficient"},
  PARTIAL_PROVIDER_RESULT: {source:"provider-result",state:"UNKNOWN",
    message:"Provider response contains partial success and unknown targets"},
  CROSS_TENANT_REFERENCE: {source:"tenant-boundary",state:"ERROR",
    message:"Source identifier claims a foreign organization"},
  APPROVAL_EXPIRED: {source:"authorization",state:"UNKNOWN",
    message:"Existing approval is outside its validity period"},
  APPROVER_IS_REQUESTER: {source:"segregation",state:"ERROR",
    message:"The requester has attempted to approve their own action"},
  DESTRUCTIVE_ACTION_REQUEST: {source:"destructive-action",state:"DECLARED",
    message:"Urgent destructive operation has been requested without independent confirmation"},
  EXECUTOR_UNAVAILABLE: {source:"action-executor",state:"ERROR",
    message:"No authorized executor is available"},
  INCOMPLETE_RECIPIENTS: {source:"message-trace",state:"UNKNOWN",
    message:"Phishing recipient population could be incomplete"},
  RANSOMWARE_SPREAD: {source:"endpoint-investigation",state:"DECLARED",
    message:"Lateral movement is suspected but unverified"},
  PAYMENT_CHANGE_PRESSURE: {source:"finance-request",state:"DECLARED",
    message:"Urgent payment account change request lacks callback verification"},
  LOSS_OF_BACKUPS: {source:"backup-service",state:"UNKNOWN",
    message:"Recovery point integrity cannot be independently established"},
  MFA_RESET_PRESSURE: {source:"identity-policy",state:"DECLARED",
    message:"Suspected attacker requests immediate MFA reset"},
  INCOMPLETE_INVENTORY: {source:"asset-inventory",state:"UNKNOWN",
    message:"No full device inventory is available"},
  ALERT_FALSE_POSITIVE: {source:"alert-feed",state:"UNKNOWN",
    message:"Alert truthfulness is disputed and not independently resolved"},
  PROVIDER_SCOPE_MISMATCH: {source:"provider-scope",state:"ERROR",
    message:"The granted scopes do not match requested operation"},
};
const presets: Record<IncidentType, TabletopFault[]> = {
  COMPROMISED_ACCOUNT: [
    "MISSING_TELEMETRY","PRIVILEGED_ACCOUNT","MFA_RESET_PRESSURE",
    "APPROVAL_EXPIRED","PARTIAL_PROVIDER_RESULT"],
  PHISHING_CAMPAIGN: [
    "NO_MAILBOX_ACCESS","INCOMPLETE_RECIPIENTS","SOURCE_THROTTLING",
    "DESTRUCTIVE_ACTION_REQUEST","PARTIAL_PROVIDER_RESULT"],
  RANSOMWARE: [
    "RANSOMWARE_SPREAD","LOSS_OF_BACKUPS","UNKNOWN_DEVICE",
    "INCOMPLETE_INVENTORY","EXECUTOR_UNAVAILABLE"],
  LOST_DEVICE: [
    "UNKNOWN_DEVICE","STALE_EVIDENCE","INCOMPLETE_INVENTORY",
    "APPROVER_IS_REQUESTER","DESTRUCTIVE_ACTION_REQUEST"],
  PAYMENT_FRAUD: [
    "PAYMENT_CHANGE_PRESSURE","ALERT_FALSE_POSITIVE","APPROVER_IS_REQUESTER",
    "MISSING_TELEMETRY","PROVIDER_SCOPE_MISMATCH"],
};
function pseudoRandom(seed: number, index: number) {
  let x = (seed ^ Math.imul(index+1,0x9e3779b1)) >>> 0;
  x ^= x << 13; x ^= x >>> 17; x ^= x << 5;
  return x >>> 0;
}
function riskFor(faults: TabletopFault[]) {
  return faults.some(x => [
    "RANSOMWARE_SPREAD", "DESTRUCTIVE_ACTION_REQUEST",
    "APPROVER_IS_REQUESTER", "CROSS_TENANT_REFERENCE",
    "PAYMENT_CHANGE_PRESSURE"].includes(x)) ? "P0" as const :
    faults.some(x=>["PRIVILEGED_ACCOUNT","LOSS_OF_BACKUPS",
      "PARTIAL_PROVIDER_RESULT"].includes(x)) ? "P1" as const : "P2" as const;
}
export function generateTabletopScenario(input: {
  id: string; organizationId: string; type: IncidentType;
  title: string; seed: number; at: string;
  faultCount?: number; additionalFaults?: TabletopFault[];
}): TabletopScenario {
  if (!validId(input.id) || !validId(input.organizationId) ||
      !validTime(input.at) || !INCIDENT_TYPES.includes(input.type) ||
      typeof input.title !== "string" ||
      input.title.trim().length < 5 || input.title.length > 180 ||
      !Number.isSafeInteger(input.seed) || input.seed < 0 ||
      input.seed > 0xffffffff)
    throw Error("TABLETOP_SCENARIO_INVALID");
  const faultCount = input.faultCount ?? 3;
  if (!Number.isSafeInteger(faultCount) || faultCount < 1 ||
      faultCount > 8 || (input.additionalFaults?.length ?? 0) > 8 ||
      input.additionalFaults?.some(x=>!TABLETOP_FAULTS.includes(x)))
    throw Error("TABLETOP_FAULT_OPTIONS_INVALID");
  const catalog = [...new Set([
    ...presets[input.type], ...(input.additionalFaults??[]),
    ...TABLETOP_FAULTS,
  ])];
  const scored = catalog.map((fault,i)=>({
    fault,weight:pseudoRandom(input.seed,i),
  })).sort((a,b)=>a.weight-b.weight||a.fault.localeCompare(b.fault));
  const selected = [...new Set([
    ...presets[input.type].slice(0,1),
    ...scored.map(x=>x.fault),
  ])].slice(0,faultCount);
  const book=getIncidentPlaybook(input.type);
  const scriptedSignals=selected.map((fault,i)=>{
    const base=FAULT_CLASS[fault];
    return {id:"inject-"+String(i+1).padStart(2,"0"),
      fault,source:base.source,state:base.state,trusted:false as const,
      message:base.message};
  });
  return {
    schema:"cyberpilot.incident.tabletop.scenario.v1",
    id:input.id,organizationId:input.organizationId,
    incidentType:input.type,title:input.title,
    createdAt:input.at,scenarioSeed:input.seed,
    playbookDigest:digest(book),
    injectedFaults:selected,activeStepIds:book.steps.map(x=>x.id),
    startingState:"UNKNOWN",scriptedSignals,
    injectedRisk:riskFor(selected),
    independentProviderEvidence:false,
    liveProviderCredential:false,tenantConsentForWrites:false,
  };
}
export function validateTabletopScenario(s: TabletopScenario): string[] {
  const problems:string[]=[];
  if (s.schema!=="cyberpilot.incident.tabletop.scenario.v1" ||
      !validId(s.id)||!validId(s.organizationId)||
      !validTime(s.createdAt)||
      !INCIDENT_TYPES.includes(s.incidentType) ||
      !Number.isSafeInteger(s.scenarioSeed) ||
      s.scenarioSeed<0 || s.scenarioSeed>0xffffffff)
    problems.push("SCENARIO_HEADER_INVALID");
  let book:ReturnType<typeof getIncidentPlaybook>|null=null;
  try{book=getIncidentPlaybook(s.incidentType);}catch{
    problems.push("PLAYBOOK_UNAVAILABLE");
  }
  if(book&&(s.playbookDigest!==digest(book) ||
    JSON.stringify(s.activeStepIds)!==
    JSON.stringify(book.steps.map(x=>x.id))))
    problems.push("PLAYBOOK_VERSION_DRIFT");
  if(!Array.isArray(s.injectedFaults)||s.injectedFaults.length<1||
      s.injectedFaults.length>8 ||
      s.injectedFaults.some(x=>!TABLETOP_FAULTS.includes(x)) ||
      new Set(s.injectedFaults).size!==s.injectedFaults.length)
    problems.push("FAULT_CATALOG_INVALID");
  if(!Array.isArray(s.scriptedSignals) ||
      s.scriptedSignals.length!==s.injectedFaults.length ||
      s.scriptedSignals.some((signal,i)=>
        signal.fault!==s.injectedFaults[i] ||signal.trusted!==false||
        signal.source!==FAULT_CLASS[signal.fault]?.source ||
        signal.state!==FAULT_CLASS[signal.fault]?.state))
    problems.push("SIGNAL_INTEGRITY_INVALID");
  if(s.independentProviderEvidence!==false ||
      s.liveProviderCredential!==false ||
      s.tenantConsentForWrites!==false)
    problems.push("UNSUPPORTED_LIVE_CLAIM");
  return problems;
}
export function createTabletopExercise(s: TabletopScenario): TabletopExercise {
  const issues=validateTabletopScenario(s);
  if(issues.length)throw Error("TABLETOP_SCENARIO_REJECTED:"+issues.join(","));
  const result={
    schema:"cyberpilot.incident.tabletop.exercise.v1" as const,
    organizationId:s.organizationId,scenarioId:s.id,incidentType:s.incidentType,
    scenarioDigest:digest(s),revision:0,status:"RUNNING" as const,
    createdAt:s.createdAt,updatedAt:s.createdAt,
    steps:s.activeStepIds.map(stepId=>({
      stepId,state:"NOT_REVIEWED" as const,revision:0,
      touchedAt:null,lastActorRole:null,evidenceRequested:false,
      manualVerificationRequested:false,escalated:false,
      independentApprovalRequested:false,sourceFaults:s.injectedFaults,
      actionsAttempted:0,unsupportedAssertionsRejected:0,
    })),events:[] as TabletopEvent[],acceptedMoves:0,rejectedMoves:0,
    unsafeOperationsBlocked:0,unknownsPreserved:0,
    externalProviderWrites:0 as const,
    operationalContainmentProven:false as const,
  };
  return {...result,exerciseDigest:digest(result)};
}
function checkMove(s: TabletopScenario, e: TabletopExercise, m: TabletopMove) {
  if(validateTabletopScenario(s).length ||
      e.organizationId!==s.organizationId ||e.scenarioId!==s.id ||
      e.scenarioDigest!==digest(s) ||
      !validId(m.id)||!validTime(m.at)||m.at<e.updatedAt||
      m.at<s.createdAt||!stepFor(s.incidentType,m.stepId) ||
      typeof m.reason!=="string"||m.reason.length<5||m.reason.length>1000 ||
      !["INCIDENT_COMMANDER","SECURITY_REVIEWER","IT_OPERATOR",
        "FINANCE_APPROVER","LEGAL_REVIEWER","EVIDENCE_COLLECTOR"]
        .includes(m.actorRole) ||
      !["DECLARE_UNKNOWN","COLLECT_EVIDENCE","ESCALATE",
        "REQUEST_INDEPENDENT_APPROVAL","MARK_PROVEN",
        "SEND_PROVIDER_COMMAND","SKIP_STEP",
        "REQUEST_MANUAL_VERIFICATION"].includes(m.command))
    throw Error("TABLETOP_MOVE_INVALID");
  const {exerciseDigest,...unsigned}=e;
  if(exerciseDigest!==digest(unsigned))throw Error("TABLETOP_EXERCISE_TAMPERED");
  if(e.revision!==e.events.length)
    throw Error("TABLETOP_EVENT_REVISION_MISMATCH");
  if(e.events.some(x=>x.moveId===m.id))
    throw Error("TABLETOP_MOVE_REPLAY");
}
function allowedMove(step:IncidentStep,m:TabletopMove) {
  if(m.assertedIndependentEvidence||m.assertedExternalCompletion)
    return {valid:false,code:"FALSE_PROVIDER_PROOF_REJECTED"};
  if(m.command==="MARK_PROVEN")
    return {valid:false,code:"TABLETOP_CANNOT_PROVE_REAL_OUTCOME"};
  if(m.command==="SEND_PROVIDER_COMMAND")
    return {valid:false,code:"TABLETOP_PROVIDER_WRITE_FORBIDDEN"};
  if(m.command==="SKIP_STEP"&&
      (step.requiresApproval||step.risk!=="READ_ONLY"))
    return {valid:false,code:"HIGH_RISK_STEP_CANNOT_BE_SKIPPED"};
  if(m.command==="REQUEST_INDEPENDENT_APPROVAL"&&!step.requiresApproval)
    return {valid:false,code:"STEP_NOT_REQUIRING_APPROVAL"};
  return {valid:true,code:"ACCEPTED"};
}
function nextState(command:TabletopDecision):TabletopStepState["state"] {
  switch(command) {
    case "DECLARE_UNKNOWN":return "UNKNOWN";
    case "ESCALATE":return "ESCALATED";
    case "COLLECT_EVIDENCE":return "EVIDENCE_REQUESTED";
    case "REQUEST_INDEPENDENT_APPROVAL":return "APPROVAL_REQUESTED";
    case "REQUEST_MANUAL_VERIFICATION":return "READY_FOR_MANUAL_REVIEW";
    default:return "UNKNOWN";
  }
}
export function applyTabletopMove(
  scenario:TabletopScenario,exercise:TabletopExercise,move:TabletopMove,
  expectedRevision:number,
):TabletopOutcome {
  checkMove(scenario,exercise,move);
  if(exercise.status!=="RUNNING")throw Error("TABLETOP_EXERCISE_CLOSED");
  if(expectedRevision!==exercise.revision)
    throw Error("TABLETOP_CONCURRENT_REVISION_CONFLICT");
  const step=stepFor(scenario.incidentType,move.stepId)!;
  const verdict=allowedMove(step,move);
  const previous=exercise.steps.find(x=>x.stepId===move.stepId)!;
  const change=verdict.valid?nextState(move.command):previous.state;
  const revision=exercise.revision+1;
  const event:TabletopEvent={
    revision,moveId:move.id,stepId:move.stepId,
    command:move.command,actorRole:move.actorRole,at:move.at,
    accepted:verdict.valid,code:verdict.code,
    previousGate:previous.state,nextGate:change,
    detailsDigest:digest({
      moveId:move.id,reason:move.reason,command:move.command,
      role:move.actorRole,scenarioDigest:exercise.scenarioDigest,
    }),
    providerWrites:0,liveSecurityBenefitProven:false,
  };
  const steps=exercise.steps.map(x=>x.stepId!==move.stepId?x:{
    ...x,state:change,revision,
    touchedAt:move.at,lastActorRole:move.actorRole,
    evidenceRequested:x.evidenceRequested||verdict.valid&&
      move.command==="COLLECT_EVIDENCE",
    manualVerificationRequested:x.manualVerificationRequested||verdict.valid&&
      move.command==="REQUEST_MANUAL_VERIFICATION",
    escalated:x.escalated||verdict.valid&&move.command==="ESCALATE",
    independentApprovalRequested:x.independentApprovalRequested||verdict.valid&&
      move.command==="REQUEST_INDEPENDENT_APPROVAL",
    actionsAttempted:x.actionsAttempted+1,
    unsupportedAssertionsRejected:x.unsupportedAssertionsRejected+
      (verdict.valid?0:1),
  });
  const next={
    schema:exercise.schema,
    organizationId:exercise.organizationId,
    scenarioId:exercise.scenarioId,incidentType:exercise.incidentType,
    scenarioDigest:exercise.scenarioDigest,revision,
    status:exercise.status,createdAt:exercise.createdAt,updatedAt:move.at,
    steps,events:[...exercise.events,event],
    acceptedMoves:exercise.acceptedMoves+(verdict.valid?1:0),
    rejectedMoves:exercise.rejectedMoves+(verdict.valid?0:1),
    unsafeOperationsBlocked:exercise.unsafeOperationsBlocked+
      (!verdict.valid&&["MARK_PROVEN","SEND_PROVIDER_COMMAND",
        "SKIP_STEP"].includes(move.command)?1:0),
    unknownsPreserved:exercise.unknownsPreserved+
      (verdict.valid&&move.command==="DECLARE_UNKNOWN"?1:0),
    externalProviderWrites:0 as const,
    operationalContainmentProven:false as const,
  };
  return {
    accepted:verdict.valid,code:verdict.code,
    exercise:{...next,exerciseDigest:digest(next)},
    event,providerWrites:0,realWorldRemediationVerified:false,
  };
}
export function reviewTabletopExercise(
  scenario:TabletopScenario,exercise:TabletopExercise,at:string,
) {
  if(!validTime(at)||at<exercise.updatedAt ||
      validateTabletopScenario(scenario).length ||
      exercise.scenarioDigest!==digest(scenario))
    throw Error("TABLETOP_REVIEW_INVALID");
  const touched=new Set(exercise.events.filter(x=>x.accepted).map(x=>x.stepId));
  const required=scenario.activeStepIds;
  const unreviewed=required.filter(x=>!touched.has(x));
  const unsafes=exercise.events.filter(x=>!x.accepted&&
    ["SEND_PROVIDER_COMMAND","MARK_PROVEN","SKIP_STEP"].includes(x.command));
  const roleCoverage=[...new Set(exercise.events.filter(x=>x.accepted)
    .map(x=>x.actorRole))].sort();
  const digestEvidence=digest({
    scenarioDigest:exercise.scenarioDigest,
    exerciseDigest:exercise.exerciseDigest,
    at,unreviewed,unsafe:unsafes.map(x=>x.moveId),roleCoverage,
  });
  return {
    schema:"cyberpilot.incident.tabletop.review.v1" as const,
    organizationId:scenario.organizationId,scenarioId:scenario.id,
    incidentType:scenario.incidentType,reviewedAt:at,
    scenarioSeed:scenario.scenarioSeed,
    decisionsRecorded:exercise.events.length,unsafeAttempts:unsafes.length,
    unreviewedSteps:unreviewed,
    approvedForExerciseDebrief:unreviewed.length===0&&
      exercise.rejectedMoves===0,
    preservationOfUnknowns:exercise.unknownsPreserved,
    reviewerRoles:roleCoverage,missingRoleCoverage:
      (["INCIDENT_COMMANDER","SECURITY_REVIEWER"] as const)
      .filter(x=>!roleCoverage.includes(x)),
    evidenceDigest:digestEvidence,
    technicalContainmentVerified:false as const,
    customerSecurityImprovementEstablished:false as const,
    providerWrites:0 as const,
  };
}
