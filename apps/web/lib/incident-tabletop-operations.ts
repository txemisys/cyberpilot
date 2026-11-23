import { createHash } from "node:crypto";
import { getIncidentPlaybook, type IncidentType } from "./incident-playbook-catalog";
import { generateTabletopScenario, createTabletopExercise,
  applyTabletopMove, reviewTabletopExercise,
  type TabletopFault, type TabletopMove,
  type TabletopScenario, type TabletopExercise }
  from "./incident-tabletop-domain";
export type TabletopExercisePlan = {
  schema: "cyberpilot.incident.tabletop.plan.v1";
  scenarioId: string; organizationId: string; incidentType: IncidentType;
  scenarioDigest: string; faultCount: number;
  injects: Array<{ id: string; fault: TabletopFault; source: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM";
    facilitatorPrompt: string; expectedGuardrail: string;
    allowedExerciseOutcomes: string[];
    noLiveProviderOperation: true }>;
  walkthrough: Array<{ stepId: string; stageTitle: string;
    targetMinutes: number; risk: string; approvalRequired: boolean;
    role: string; expectedProof: string[];
    fallback: string; stopConditions: string[] }>;
  totalEstimatedMinutes: number; humanFacilitatorRequired: true;
  realTenantRequired: false; providerWrites: 0;
};
const severityOf=(fault:TabletopFault):"CRITICAL"|"HIGH"|"MEDIUM"=>
  ["DESTRUCTIVE_ACTION_REQUEST","RANSOMWARE_SPREAD","PAYMENT_CHANGE_PRESSURE",
    "CROSS_TENANT_REFERENCE","APPROVER_IS_REQUESTER"].includes(fault) ?
    "CRITICAL" : ["PARTIAL_PROVIDER_RESULT","PRIVILEGED_ACCOUNT",
    "LOSS_OF_BACKUPS","SOURCE_THROTTLING"].includes(fault) ?
    "HIGH" : "MEDIUM";
const expectedForFault=(fault:TabletopFault):string=>{
  if(["CROSS_TENANT_REFERENCE","PROVIDER_SCOPE_MISMATCH"].includes(fault))
    return "Reject any cross-tenant or unauthorized provider scope";
  if(["DESTRUCTIVE_ACTION_REQUEST","APPROVER_IS_REQUESTER",
      "APPROVAL_EXPIRED"].includes(fault))
    return "Require independent, current, scope-bound approval and never dispatch";
  if(["UNKNOWN_DEVICE","INCOMPLETE_INVENTORY"].includes(fault))
    return "Mark physical identity UNKNOWN; do not isolate or wipe unverified targets";
  if(["MISSING_TELEMETRY","STALE_EVIDENCE","LOSS_OF_BACKUPS"].includes(fault))
    return "Preserve UNKNOWN and request independent, timestamped proof";
  if(["SOURCE_THROTTLING","EXECUTOR_UNAVAILABLE","NO_MAILBOX_ACCESS"].includes(fault))
    return "Preserve error state and use a documented manual fallback";
  return "Escalate uncertainty without converting a statement into provider proof";
};
export function planTabletopExercise(s:TabletopScenario):TabletopExercisePlan {
  const book=getIncidentPlaybook(s.incidentType);
  const injects=s.scriptedSignals.map(signal=>({
    id:signal.id,fault:signal.fault,source:signal.source,
    severity:severityOf(signal.fault),
    facilitatorPrompt:signal.message,
    expectedGuardrail:expectedForFault(signal.fault),
    allowedExerciseOutcomes:["DECLARE_UNKNOWN","COLLECT_EVIDENCE","ESCALATE",
      "REQUEST_INDEPENDENT_APPROVAL","REQUEST_MANUAL_VERIFICATION"],
    noLiveProviderOperation:true as const,
  }));
  const walkthrough=book.steps.map(step=>({
    stepId:step.id,stageTitle:step.title,
    targetMinutes:step.targetMinutes,risk:step.risk,
    approvalRequired:step.requiresApproval,role:step.suggestedOwner,
    expectedProof:step.proofRequired,fallback:step.fallback,
    stopConditions:[
      ...(step.requiresApproval?["No independent approval on exact target"]:[]),
      "No independent source evidence or missing permissions",
      "Target tenant or affected object identity not confirmed",
      ...(step.risk==="DESTRUCTIVE"?
        ["No documented rollback, preview or blast-radius review"]:[]),
    ],
  }));
  return {
    schema:"cyberpilot.incident.tabletop.plan.v1",
    scenarioId:s.id,organizationId:s.organizationId,
    incidentType:s.incidentType,
    scenarioDigest:createHash("sha256").update(JSON.stringify(s)).digest("hex"),
    faultCount:injects.length,injects,walkthrough,
    totalEstimatedMinutes:Math.min(720,walkthrough.reduce((n,x)=>
      n+x.targetMinutes,0)),
    humanFacilitatorRequired:true,realTenantRequired:false,
    providerWrites:0,
  };
}
export type TabletopDebrief = {
  schema: "cyberpilot.incident.tabletop.debrief.v1";
  scenarioId: string; organizationId: string; scenarioType: IncidentType;
  exerciseRevision: number; exerciseDigest: string;
  reviewedAt: string; stageCoveragePercent: number;
  safetyCompliancePercent: number;
  readiness: "NEEDS_PRACTICE" | "FACILITATOR_REVIEW" | "OFFLINE_READY";
  findings: Array<{code:string;severity:string;reason:string;
    correctiveAction:string;providerVerificationNeeded:boolean}>;
  coveredStages: string[]; missingStages: string[];
  violations: number; blockedCommands: number;
  reproducibilityKey: string; externalContainmentProven: false;
  securityImprovementMeasured: false;
};
export function debriefTabletopExercise(
  scenario:TabletopScenario,exercise:TabletopExercise,reviewedAt:string,
):TabletopDebrief {
  const result=reviewTabletopExercise(scenario,exercise,reviewedAt);
  const plan=planTabletopExercise(scenario);
  const accepted=new Set(exercise.events.filter(x=>x.accepted).map(x=>x.stepId));
  const coveredStages=plan.walkthrough.filter(x=>accepted.has(x.stepId))
    .map(x=>x.stepId);
  const missingStages=plan.walkthrough.filter(x=>!accepted.has(x.stepId))
    .map(x=>x.stepId);
  const stageCoveragePercent=Math.round(coveredStages.length/
    Math.max(1,plan.walkthrough.length)*100);
  const safe=exercise.events.filter(x=>x.accepted).length;
  const safetyCompliancePercent=Math.round(safe/
    Math.max(1,exercise.events.length)*100);
  const findings:TabletopDebrief["findings"]=[];
  for(const id of missingStages){
    findings.push({code:"STAGE_UNREVIEWED:"+id,severity:"MEDIUM",
      reason:"Playbook stage not addressed by exercise decisions",
      correctiveAction:"Assign facilitator and exercise the missing stage",
      providerVerificationNeeded:false});
  }
  if(exercise.unsafeOperationsBlocked){
    findings.push({code:"UNSAFE_OPERATION_ATTEMPTS",severity:"HIGH",
      reason:"Exercise contained unsupported provider commands or proof claims",
      correctiveAction:"Review stop conditions and segregated approval requirements",
      providerVerificationNeeded:true});
  }
  for(const role of result.missingRoleCoverage){
    findings.push({code:"ROLE_NOT_EXERCISED:"+role,severity:"MEDIUM",
      reason:"Required incident role not represented in the replay",
      correctiveAction:"Include the role in another tabletop session",
      providerVerificationNeeded:false});
  }
  if(!exercise.unknownsPreserved){
    findings.push({code:"NO_EXPLICIT_UNKNOWN_HANDLING",severity:"HIGH",
      reason:"Participants did not explicitly preserve uncertainty",
      correctiveAction:"Rehearse unknown and unavailable source paths",
      providerVerificationNeeded:false});
  }
  if(exercise.events.length===0){
    findings.push({code:"NO_DECISIONS_RECORDED",severity:"HIGH",
      reason:"No operator decisions were supplied",
      correctiveAction:"Run the tabletop through at least one exercise step",
      providerVerificationNeeded:false});
  }
  const readiness=stageCoveragePercent===100&&
      exercise.rejectedMoves===0&&
      result.missingRoleCoverage.length===0&&
      exercise.unknownsPreserved>0 ?
      "OFFLINE_READY" as const :
      stageCoveragePercent>=60&&safetyCompliancePercent>=80 ?
      "FACILITATOR_REVIEW" as const : "NEEDS_PRACTICE" as const;
  return {
    schema:"cyberpilot.incident.tabletop.debrief.v1",
    scenarioId:scenario.id,organizationId:scenario.organizationId,
    scenarioType:scenario.incidentType,
    exerciseRevision:exercise.revision,exerciseDigest:exercise.exerciseDigest,
    reviewedAt,stageCoveragePercent,safetyCompliancePercent,
    readiness,findings,coveredStages,missingStages,
    violations:exercise.rejectedMoves,
    blockedCommands:exercise.unsafeOperationsBlocked,
    reproducibilityKey:createHash("sha256").update(JSON.stringify({
      scenarioSeed:scenario.scenarioSeed,
      incidentType:scenario.incidentType,
      scenarioFaults:scenario.injectedFaults,
      exerciseDigest:exercise.exerciseDigest,
    })).digest("hex"),
    externalContainmentProven:false,
    securityImprovementMeasured:false,
  };
}
export function executeDeterministicTabletop(
  scenario:TabletopScenario,
  moves:TabletopMove[],
  reviewedAt:string,
) {
  if(!Array.isArray(moves)||moves.length>300)
    throw Error("TABLETOP_MOVE_LIMIT");
  let exercise=createTabletopExercise(scenario);
  const events=[];
  for(const move of moves){
    const outcome=applyTabletopMove(scenario,exercise,move,exercise.revision);
    exercise=outcome.exercise;
    events.push(outcome.event);
  }
  const review=reviewTabletopExercise(scenario,exercise,reviewedAt);
  const debrief=debriefTabletopExercise(scenario,exercise,reviewedAt);
  return {
    schema:"cyberpilot.incident.tabletop.replay.v1" as const,
    organizationId:scenario.organizationId,
    scenarioId:scenario.id,
    exercise,events,review,debrief,
    inputMoves:moves.length,providerWrites:0 as const,
    productionIncidentsModified:0 as const,
  };
}
export function compareTabletopDebriefs(
  before:TabletopDebrief,after:TabletopDebrief,
) {
  if(before.organizationId!==after.organizationId ||
      before.scenarioType!==after.scenarioType ||
      before.reviewedAt>after.reviewedAt)
    throw Error("TABLETOP_TREND_SCOPE_INVALID");
  const prior=new Set(before.findings.map(x=>x.code));
  const current=new Set(after.findings.map(x=>x.code));
  return {
    schema:"cyberpilot.incident.tabletop.trend.v1" as const,
    organizationId:before.organizationId,
    scenarioType:before.scenarioType,
    coverageDelta:after.stageCoveragePercent-before.stageCoveragePercent,
    complianceDelta:after.safetyCompliancePercent-before.safetyCompliancePercent,
    newFindings:[...current].filter(x=>!prior.has(x)),
    noLongerPresent:[...prior].filter(x=>!current.has(x)),
    trainingProgressOnly:true as const,
    liveIncidentRecoveryProven:false as const,
  };
}
function csv(x:unknown){
  const raw=String(x??"");
  return '"'+(/^[=+\-@\t\r]/.test(raw)?"'"+raw:raw)
    .replaceAll('"','""').replaceAll("\n"," ").replaceAll("\r"," ")+'"';
}
export function exportTabletopReplay(
  result:ReturnType<typeof executeDeterministicTabletop>,
  format:"JSON"|"CSV"|"MARKDOWN",
) {
  const manifest={
    schema:"cyberpilot.incident.tabletop.export.v1",
    result,externalProviderActions:0,independentProofOfSecurityOutcome:false,
  };
  const digest=createHash("sha256")
    .update(JSON.stringify(manifest)).digest("hex");
  const name="tabletop-"+result.scenarioId;
  if(format==="JSON")return{
    filename:name+".json",mime:"application/json",digest,
    content:JSON.stringify({...manifest,digest},null,2),
  };
  if(format==="CSV"){
    const rows=[["revision","stepId","role","decision","accepted","code"],
      ...result.exercise.events.map(x=>[
        String(x.revision),x.stepId,x.actorRole,x.command,
        String(x.accepted),x.code])];
    return{filename:name+".csv",mime:"text/csv",digest,
      content:rows.map(row=>row.map(csv).join(",")).join("\r\n")};
  }
  if(format!=="MARKDOWN")throw Error("TABLETOP_EXPORT_FORMAT_INVALID");
  const safe=(x:string)=>x.replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll("|","\\|");
  return{
    filename:name+".md",mime:"text/markdown",digest,
    content:["# Incident tabletop exercise",
      "Scenario: "+result.scenarioId,
      "Organization: "+result.organizationId,
      "Training readiness: "+result.debrief.readiness,
      "Stage coverage: "+result.debrief.stageCoveragePercent+"%",
      "Provider writes performed: 0","Digest: "+digest,"",
      "## Exercise decisions",
      ...result.exercise.events.map(x=>"- "+safe(x.command)+
        " / "+safe(x.stepId)+": "+x.code),
      "","## Follow-up actions",
      ...result.debrief.findings.map(x=>"- "+safe(x.correctiveAction)),
      "","No real incident containment has been verified.",
    ].join("\n"),
  };
}
