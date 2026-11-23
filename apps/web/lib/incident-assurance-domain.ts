import { createHash } from "node:crypto";
import { type IncidentSituation } from "./incident-situation-domain";
import { type TabletopDebrief } from "./incident-tabletop-operations";
import { getIncidentPlaybook } from "./incident-playbook-catalog";
export type AssuranceControlState = "PASS_OFFLINE" | "FAIL" |
  "UNKNOWN" | "NEEDS_REVIEW" | "NOT_APPLICABLE";
export type AssuranceCategory = "INCIDENT_GOVERNANCE" |
  "EVIDENCE_PROVENANCE" | "ASSET_ATTRIBUTION" |
  "REMEDIATION_AUTHORIZATION" | "OPERATIONAL_READINESS" |
  "TABLETOP_TRAINING" | "EXTERNAL_PROOF";
export type AssuranceControl = {
  id: string; category: AssuranceCategory; title: string;
  importance: "CRITICAL" | "HIGH" | "NORMAL";
  state: AssuranceControlState;
  reason: string; evidenceRefs: string[];
  missingEvidence: string[];
  ownerRole: string; remediationGuidance: string;
  deadlineMinutes: number | null;
  allowedAutomaticPass: boolean;
  externalSecurityOutcomeVerified: false;
};
export type AssuranceInput = {
  situation: IncidentSituation;
  tabletop: TabletopDebrief | null;
  evaluatedAt: string;
  policy: AssurancePolicy;
};
export type AssurancePolicy = {
  schema: "cyberpilot.incident.assurance.policy.v1";
  id: string; requireOwner: boolean;
  requireFullSourceScope: boolean; requireTabletopForCritical: boolean;
  requireIndependentApprovalForHighImpact: boolean;
  maxUnknownSourceCount: number; maximumPendingSteps: number;
  maxCriticalConcerns: number;
  allowHistoricalVerifiedAsProviderProof: false;
  minimumTabletopCoveragePercent: number;
  reviewIntervalHours: number;
};
export type AssuranceReport = {
  schema: "cyberpilot.incident.assurance.report.v1";
  organizationId: string; incidentId: string; playbookType: string;
  evaluatedAt: string; incidentRevision: number;
  situationDigest: string; policyId: string;
  tabletopDigest: string | null;
  controls: AssuranceControl[];
  status: "STOP" | "INCOMPLETE" | "OFFLINE_REVIEW_ELIGIBLE";
  criticalFailures: number; highFailures: number;
  unknownControls: number; passedOffline: number;
  operatorActions: Array<{controlId:string;action:string;
    ownerRole:string;priority:string;dueBy:string}>;
  riskScore: number; riskBand: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  nextReviewBy: string;
  sourceCoverage: string; incidentStatus: string;
  actuallyApprovedForProviderExecution: false;
  independentProviderContainmentVerified: false;
  securityPostureReductionMeasured: false;
  customerConsentEstablished: false;
  externallyExecutableActions: 0;
  integrityDigest: string;
};
const validTime = (x: unknown): x is string => typeof x === "string" &&
  Number.isFinite(Date.parse(x)) && new Date(x).toISOString() === x;
const validId = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const digest = (x: unknown) => createHash("sha256")
  .update(JSON.stringify(x)).digest("hex");
export const DEFAULT_ASSURANCE_POLICY: AssurancePolicy = {
  schema:"cyberpilot.incident.assurance.policy.v1",
  id:"standard-offline-assurance-v1",
  requireOwner:true,requireFullSourceScope:false,
  requireTabletopForCritical:true,
  requireIndependentApprovalForHighImpact:true,
  maxUnknownSourceCount:2,maximumPendingSteps:25,
  maxCriticalConcerns:0,
  allowHistoricalVerifiedAsProviderProof:false,
  minimumTabletopCoveragePercent:80,reviewIntervalHours:24,
};
export function validateAssurancePolicy(p:AssurancePolicy) {
  const errors:string[]=[];
  if(p.schema!=="cyberpilot.incident.assurance.policy.v1"||
    !validId(p.id))errors.push("POLICY_ID_INVALID");
  for(const key of ["requireOwner","requireFullSourceScope",
    "requireTabletopForCritical",
    "requireIndependentApprovalForHighImpact"] as const){
    if(typeof p[key]!=="boolean")errors.push("POLICY_BOOLEAN_INVALID:"+key);
  }
  if(p.allowHistoricalVerifiedAsProviderProof!==false)
    errors.push("PROVIDER_OUTCOME_SHORTCUT_FORBIDDEN");
  if(!Number.isSafeInteger(p.maxUnknownSourceCount)||
    p.maxUnknownSourceCount<0||p.maxUnknownSourceCount>3)
    errors.push("SOURCE_LIMIT_INVALID");
  if(!Number.isSafeInteger(p.maximumPendingSteps)||
    p.maximumPendingSteps<0||p.maximumPendingSteps>200)
    errors.push("PENDING_LIMIT_INVALID");
  if(!Number.isSafeInteger(p.maxCriticalConcerns)||
    p.maxCriticalConcerns<0||p.maxCriticalConcerns>200)
    errors.push("CRITICAL_LIMIT_INVALID");
  if(!Number.isSafeInteger(p.minimumTabletopCoveragePercent)||
    p.minimumTabletopCoveragePercent<0||
    p.minimumTabletopCoveragePercent>100)
    errors.push("TABLETOP_LIMIT_INVALID");
  if(!Number.isSafeInteger(p.reviewIntervalHours)||
    p.reviewIntervalHours<1||p.reviewIntervalHours>720)
    errors.push("REVIEW_INTERVAL_INVALID");
  return errors;
}
function control(
  id:string, category:AssuranceCategory,title:string,
  importance:AssuranceControl["importance"], state:AssuranceControlState,
  reason:string, evidenceRefs:string[],missingEvidence:string[],
  ownerRole:string,remediationGuidance:string,deadlineMinutes:number|null,
  allowedAutomaticPass=false,
): AssuranceControl {
  return {id,category,title,importance,state,reason,evidenceRefs,
    missingEvidence,ownerRole,remediationGuidance,deadlineMinutes,
    allowedAutomaticPass,externalSecurityOutcomeVerified:false};
}
function governance(s:IncidentSituation,p:AssurancePolicy) {
  const results:AssuranceControl[]=[];
  results.push(control("GOVERNANCE_OWNER","INCIDENT_GOVERNANCE",
    "Accountable incident owner", "HIGH",
    s.owners.unassigned&&p.requireOwner?"FAIL":"PASS_OFFLINE",
    s.owners.unassigned?"No current incident owner":"Owner is recorded in case",
    s.owners.incidentOwner?[s.owners.incidentOwner]:[],
    s.owners.unassigned?["Active tenant member assignment"]:[],
    "Organization administrator","Assign incident commander",30,true));
  results.push(control("GOVERNANCE_OPEN","INCIDENT_GOVERNANCE",
    "Case state and technical outcome are not confused","CRITICAL",
    s.caseStatus==="CLOSED"?"NEEDS_REVIEW":"PASS_OFFLINE",
    s.caseStatus==="CLOSED"?
      "Workflow closure is not provider verification":"Workflow status is explicit",
    [s.incidentSnapshotDigest],["Independent provider verification"],
    "Incident commander",
    "Review residual unknown outcomes before external closure claims",60));
  results.push(control("GOVERNANCE_PRIORITIES","INCIDENT_GOVERNANCE",
    "Critical incident alerts escalated","HIGH",
    s.concerns.filter(x=>x.urgency==="P0").length>
      p.maxCriticalConcerns?"FAIL":"PASS_OFFLINE",
    "Priority review uses stored concerns and configured policy",
    s.concerns.filter(x=>x.urgency==="P0").map(x=>x.id),
    s.concerns.some(x=>x.urgency==="P0")?
      ["Critical escalation confirmation"]:[],
    "Incident commander","Address P0 blockers and document escalation",15,true));
  results.push(control("GOVERNANCE_PENDING","INCIDENT_GOVERNANCE",
    "Playbook pending work volume","NORMAL",
    s.work.pending>p.maximumPendingSteps?"FAIL":"PASS_OFFLINE",
    "Pending stage count from persisted guided-case snapshot",
    s.stages.filter(x=>x.status==="PENDING").map(x=>x.id),
    [],"Case owner","Review pending stages and assign deadlines",240,true));
  return results;
}
function evidence(s:IncidentSituation,p:AssurancePolicy) {
  const e=s.sourceSummaries.find(x=>x.name==="EVIDENCE");
  if(!e)throw Error("ASSURANCE_EVIDENCE_SOURCE_MISSING");
  const unknownCount=s.sourceSummaries.filter(x=>
    x.availability!=="PRESENT").length;
  return [
    control("EVIDENCE_COVERAGE","EVIDENCE_PROVENANCE",
      "Source query completeness","HIGH",
      e.availability!=="PRESENT"?"UNKNOWN":
        e.missingCount||e.truncated?"NEEDS_REVIEW":"PASS_OFFLINE",
      "Selected evidence set is scoped and bounded, not population-wide proof",
      e.sourceDigest?[e.sourceDigest]:[],
      e.missingCount?["Missing explicit source records"]:[],
      "Evidence reviewer","Recover missing or truncated source observations",120,
      false),
    control("EVIDENCE_UNKNOWN_BOUND","EVIDENCE_PROVENANCE",
      "Unknown source count within configured review budget","HIGH",
      unknownCount>p.maxUnknownSourceCount?"FAIL":
        unknownCount?"NEEDS_REVIEW":"PASS_OFFLINE",
      "Source unavailability is not interpreted as safe configuration",
      s.sourceSummaries.filter(x=>x.availability!=="PRESENT")
        .map(x=>x.name),
      unknownCount?["Unobserved source coverage and retention"]:[],
      "Integration operator","Resolve unavailable source or declare partial scope",120),
    control("EVIDENCE_NO_FALSE_PROOF","EVIDENCE_PROVENANCE",
      "No stored observation treated as proof of containment","CRITICAL",
      s.actualContainmentVerified?"FAIL":"PASS_OFFLINE",
      "Provider proof is deliberately unavailable in the read-only situation room",
      [s.situationDigest],["Independent provider readback"],
      "Security reviewer","Request authenticated external verification",60),
    control("EVIDENCE_SOURCE_SCOPE","EVIDENCE_PROVENANCE",
      "Completeness is explicitly scoped","HIGH",
      p.requireFullSourceScope&&s.completeness!=="EXPLICIT_SCOPE_ONLY"?
        "FAIL":s.completeness==="UNKNOWN"?"UNKNOWN":"PASS_OFFLINE",
      "Complete selections are not proof of full customer estate coverage",
      s.sourceSummaries.map(x=>x.name+":"+x.availability),
      s.completeness!=="EXPLICIT_SCOPE_ONLY"?
        ["Remaining source scopes and manifests"]:[],
      "Evidence owner","Document exact sources and unsupported scopes",120),
  ];
}
function assets(s:IncidentSituation) {
  const source=s.sourceSummaries.find(x=>x.name==="ASSETS");
  if(!source)throw Error("ASSURANCE_ASSET_SOURCE_MISSING");
  return [
    control("ASSETS_IDENTITY","ASSET_ATTRIBUTION",
      "Asset attribution is explicit, never heuristic","CRITICAL",
      source.availability==="ABSENT"?"UNKNOWN":
        s.concerns.some(x=>x.code==="AMBIGUOUS_DEVICE_IDENTITY")?
          "FAIL":"PASS_OFFLINE",
      "Inventory records do not independently identify a physical endpoint",
      source.sourceDigest?[source.sourceDigest]:[],
      ["Trusted managed-device identity and ownership evidence"],
      "Asset administrator","Reconcile device/tenant identity before isolation",120),
    control("ASSETS_FRESHNESS","ASSET_ATTRIBUTION",
      "Current inventory observation","HIGH",
      s.work.staleAssets>0?"FAIL":
        source.availability==="ABSENT"?"UNKNOWN":"PASS_OFFLINE",
      "Historic inventory is not live telemetry",
      source.sourceDigest?[source.sourceDigest]:[],
      s.work.staleAssets?["Fresh inventory observation"]:[],
      "IT operator","Refresh authorized asset inventory",240,true),
    control("ASSETS_ADVISORIES","ASSET_ATTRIBUTION",
      "Candidate vulnerabilities are reviewed","NORMAL",
      s.work.possibleAdvisories?"NEEDS_REVIEW":
        source.availability==="ABSENT"?"UNKNOWN":"PASS_OFFLINE",
      "An OSV advisory candidate does not prove exploitation",
      source.sourceDigest?[source.sourceDigest]:[],
      s.work.possibleAdvisories?["Precise affected product versions"]:[],
      "Vulnerability analyst","Review relevant OSV query results",240),
  ];
}
function remediation(s:IncidentSituation,p:AssurancePolicy) {
  const source=s.sourceSummaries.find(x=>x.name==="REMEDIATION");
  if(!source)throw Error("ASSURANCE_REMEDIATION_SOURCE_MISSING");
  const unapproved=s.stages.filter(x=>
    x.approvalNeeded&&!x.approvalRecorded);
  return [
    control("REMEDIATION_DUTIES","REMEDIATION_AUTHORIZATION",
      "Independent approvals before high impact operations","CRITICAL",
      p.requireIndependentApprovalForHighImpact&&unapproved.length?
        "FAIL":"PASS_OFFLINE",
      "A playbook approval is a record, not a grant for LIVE executor operations",
      s.stages.filter(x=>x.approvalRecorded).map(x=>x.id),
      unapproved.map(x=>"Approval:"+x.id),
      "Security approver","Acquire independent, scope-bound authorization",30),
    control("REMEDIATION_NO_AUTOMATION","REMEDIATION_AUTHORIZATION",
      "Unsupported executor modes blocked","CRITICAL",
      s.work.automatedModeTargets>0?"FAIL":"PASS_OFFLINE",
      "No automatic provider action may run from offline workflow",
      source.sourceDigest?[source.sourceDigest]:[],
      s.work.automatedModeTargets?["Dedicated executor consent"]:[],
      "Security officer","Reject unsafe automated remediation",15),
    control("REMEDIATION_WORK_ITEMS","REMEDIATION_AUTHORIZATION",
      "Work items reconciled with current findings","HIGH",
      s.work.workItemsIncomplete?"NEEDS_REVIEW":
        source.availability==="ABSENT"?"UNKNOWN":"PASS_OFFLINE",
      "Task completion is separate from actual provider-side outcome",
      source.sourceDigest?[source.sourceDigest]:[],
      s.work.workItemsIncomplete?["Completed work item verification"]:[],
      "Remediation owner","Follow up incomplete actions",120),
    control("REMEDIATION_PROVIDER_PROOF","EXTERNAL_PROOF",
      "Independent provider post-action readback","CRITICAL","UNKNOWN",
      "No proof can be inferred from incident state, work items, or tabletop training",
      [],["Signed or authenticated provider-side action receipt",
        "Post-action verification readback",
        "Object-specific failure reconciliation"],
      "Independent security verifier",
      "Validate with consented external provider through separate executor",
      null),
  ];
}
function operational(s:IncidentSituation) {
  const missing=s.concerns.filter(x=>x.urgency==="P0");
  return [
    control("OPS_PRIORITIES","OPERATIONAL_READINESS",
      "Critical concerns are assigned for review","HIGH",
      missing.length?"NEEDS_REVIEW":"PASS_OFFLINE",
      "Priorities are operational recommendations, not security posture scores",
      missing.map(x=>x.id),
      missing.length?["Recorded P0 owner handoff"]:[],
      "Incident commander","Acknowledge and assign all P0 concerns",30),
    control("OPS_CASE_REVISION","OPERATIONAL_READINESS",
      "Case revision and digest available","HIGH",
      s.revision>0&&s.incidentSnapshotDigest?"PASS_OFFLINE":"FAIL",
      "Case state is included with a reproducible source digest",
      [s.incidentSnapshotDigest],
      [],"Security reviewer","Reconcile persisted case digest and revision",60,true),
    control("OPS_BOUNDED_SCOPE","OPERATIONAL_READINESS",
      "Source truncation and gaps visible","NORMAL",
      s.sourceSummaries.some(x=>x.truncated||x.missingCount)?
        "NEEDS_REVIEW":"PASS_OFFLINE",
      "Bounded sampling cannot make population-wide assurance claims",
      s.sourceSummaries.map(x=>x.name+":"+x.availability),
      s.sourceSummaries.filter(x=>x.truncated).map(x=>x.name),
      "Source owner","Review all required source pages",240),
  ];
}
function tabletop(s:IncidentSituation,t:TabletopDebrief|null,p:AssurancePolicy) {
  const critical=s.severity==="CRITICAL";
  if(!t)return [control("TABLETOP_READINESS","TABLETOP_TRAINING",
    "Playbook training scenario review",critical?"HIGH":"NORMAL",
    critical&&p.requireTabletopForCritical?"FAIL":"UNKNOWN",
    "No matching offline training report supplied",
    [],critical?["Tabletop review with current playbook"]:[],
    "Incident facilitator","Run deterministic exercise with stop conditions",
    240)];
  if(t.organizationId!==s.organizationId||t.scenarioType!==s.playbookType)
    throw Error("ASSURANCE_TABLETOP_SCOPE_INVALID");
  return [
    control("TABLETOP_READINESS","TABLETOP_TRAINING",
      "Playbook training scenario review","NORMAL",
      t.stageCoveragePercent>=p.minimumTabletopCoveragePercent &&
        t.violations===0?"PASS_OFFLINE":"NEEDS_REVIEW",
      "Training metrics demonstrate rehearsal only",
      [t.exerciseDigest],
      t.stageCoveragePercent<p.minimumTabletopCoveragePercent?
        ["Additional rehearsal steps"]:[],
      "Incident facilitator","Rehearse missing stages and guardrail violations",
      240,true),
    control("TABLETOP_FALSE_CONTAINMENT","TABLETOP_TRAINING",
      "Tabletop never claims provider containment","CRITICAL",
      t.externalContainmentProven?"FAIL":"PASS_OFFLINE",
      "Simulation verdict is separate from actual customer operations",
      [t.reproducibilityKey],
      ["Provider-side independent evidence"],
      "Security reviewer","Never promote training outcomes into LIVE verification",
      60),
  ];
}
export function assessIncidentAssurance(input:AssuranceInput):AssuranceReport {
  const {situation:s,tabletop:t,policy:p}=input;
  if(!validTime(input.evaluatedAt)||input.evaluatedAt<s.evaluatedAt ||
      validateAssurancePolicy(p).length||
      !validId(s.organizationId)||!validId(s.incidentId) ||
      s.externalWrites!==0||s.actualContainmentVerified!==false ||
      s.sourceSummaries.length!==3)
    throw Error("ASSURANCE_INPUT_INVALID");
  const controls=[
    ...governance(s,p),...evidence(s,p),...assets(s),
    ...remediation(s,p),...operational(s),...tabletop(s,t,p),
  ];
  const ids=new Set(controls.map(x=>x.id));
  if(ids.size!==controls.length)throw Error("ASSURANCE_DUPLICATE_CONTROL");
  const criticalFailures=controls.filter(x=>x.importance==="CRITICAL"&&
    x.state==="FAIL").length;
  const highFailures=controls.filter(x=>x.importance==="HIGH"&&
    x.state==="FAIL").length;
  const unknownControls=controls.filter(x=>x.state==="UNKNOWN").length;
  const passedOffline=controls.filter(x=>x.state==="PASS_OFFLINE").length;
  const status=criticalFailures||highFailures?"STOP" as const:
    unknownControls||controls.some(x=>x.state==="NEEDS_REVIEW")?
    "INCOMPLETE" as const:"OFFLINE_REVIEW_ELIGIBLE" as const;
  const riskScore=Math.min(100,criticalFailures*20+
    highFailures*10+unknownControls*4+
    controls.filter(x=>x.state==="NEEDS_REVIEW").length*3);
  const riskBand=riskScore>=70?"CRITICAL" as const:
    riskScore>=40?"HIGH" as const:riskScore>=15?"MEDIUM" as const:
    "LOW" as const;
  const operatorActions=controls.filter(x=>x.state!=="PASS_OFFLINE"&&
    x.state!=="NOT_APPLICABLE").map(x=>({
      controlId:x.id,action:x.remediationGuidance,
      ownerRole:x.ownerRole,priority:x.importance,
      dueBy:new Date(Date.parse(input.evaluatedAt)+
        (x.deadlineMinutes??p.reviewIntervalHours*60)*60000).toISOString(),
    }));
  const report={
    schema:"cyberpilot.incident.assurance.report.v1" as const,
    organizationId:s.organizationId,incidentId:s.incidentId,
    playbookType:s.playbookType,evaluatedAt:input.evaluatedAt,
    incidentRevision:s.revision,situationDigest:s.situationDigest,
    policyId:p.id,tabletopDigest:t?.exerciseDigest??null,
    controls,status,criticalFailures,highFailures,unknownControls,
    passedOffline,operatorActions,riskScore,riskBand,
    nextReviewBy:new Date(Date.parse(input.evaluatedAt)+
      p.reviewIntervalHours*3600000).toISOString(),
    sourceCoverage:s.completeness,incidentStatus:s.caseStatus,
    actuallyApprovedForProviderExecution:false as const,
    independentProviderContainmentVerified:false as const,
    securityPostureReductionMeasured:false as const,
    customerConsentEstablished:false as const,
    externallyExecutableActions:0 as const,
  };
  return {...report,integrityDigest:digest(report)};
}
export function compareAssuranceReports(before:AssuranceReport,after:AssuranceReport) {
  if(before.organizationId!==after.organizationId ||
      before.incidentId!==after.incidentId ||
      before.policyId!==after.policyId ||
      before.evaluatedAt>after.evaluatedAt)
    throw Error("ASSURANCE_COMPARISON_SCOPE_INVALID");
  const previous=new Map(before.controls.map(x=>[x.id,x]));
  const current=new Map(after.controls.map(x=>[x.id,x]));
  return {
    schema:"cyberpilot.incident.assurance.comparison.v1" as const,
    organizationId:before.organizationId,incidentId:before.incidentId,
    statusesChanged:[...current.values()].filter(x=>previous.has(x.id)&&
      previous.get(x.id)!.state!==x.state).map(x=>({
        id:x.id,previous:previous.get(x.id)!.state,current:x.state,
      })),
    newControls:[...current.keys()].filter(x=>!previous.has(x)),
    retiredControls:[...previous.keys()].filter(x=>!current.has(x)),
    riskScoreDelta:after.riskScore-before.riskScore,
    scopeComparable:before.sourceCoverage===after.sourceCoverage,
    actualCustomerRiskReductionProven:false as const,
    externalActionCompletionProven:false as const,
  };
}
