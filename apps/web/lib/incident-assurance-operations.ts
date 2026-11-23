import { createHash } from "node:crypto";
import type { AssuranceControl, AssuranceReport,
  AssuranceCategory } from "./incident-assurance-domain";
import { compareAssuranceReports } from "./incident-assurance-domain";
export type AssuranceWorkPacket = {
  schema: "cyberpilot.incident.assurance.work-packet.v1";
  incidentId: string; organizationId: string; evaluatedAt: string;
  categories: Array<{category:AssuranceCategory;items:number;
    failures:number;unknowns:number;reviewNeeded:number;
    highestRisk:string;controls:string[]}>;
  prioritization: Array<{id:string;category:AssuranceCategory;
    action:string;owner:string;deadline:string;
    critical:boolean;requiresProviderProof:boolean}>;
  humanSignoffConditions: string[]; outstandingCount: number;
  externalExecutionEnabled: false; clientSecurityImprovementVerified: false;
};
const categories:AssuranceCategory[]=[
  "INCIDENT_GOVERNANCE","EVIDENCE_PROVENANCE","ASSET_ATTRIBUTION",
  "REMEDIATION_AUTHORIZATION","OPERATIONAL_READINESS",
  "TABLETOP_TRAINING","EXTERNAL_PROOF",
];
const weights:Record<AssuranceControl["importance"],number>=
  {CRITICAL:3,HIGH:2,NORMAL:1};
export function prepareAssuranceWorkPacket(report:AssuranceReport):
  AssuranceWorkPacket {
  if(report.controls.length>1000||
      report.controls.some(x=>x.externalSecurityOutcomeVerified))
    throw Error("ASSURANCE_PACKET_INVALID");
  const groups=categories.map(category=>{
    const controls=report.controls.filter(x=>x.category===category);
    const failed=controls.filter(x=>x.state==="FAIL");
    const unresolved=controls.filter(x=>x.state==="NEEDS_REVIEW");
    return {
      category,items:controls.length,failures:failed.length,
      unknowns:controls.filter(x=>x.state==="UNKNOWN").length,
      reviewNeeded:unresolved.length,
      highestRisk:controls.reduce((current,x)=>
        weights[x.importance]>weights[current]?x.importance:current,
        "NORMAL" as AssuranceControl["importance"]),
      controls:controls.map(x=>x.id),
    };
  });
  const pending=report.controls.filter(x=>
    x.state==="FAIL"||x.state==="UNKNOWN"||
    x.state==="NEEDS_REVIEW");
  const priorities=pending.map(x=>({
    id:x.id,category:x.category,action:x.remediationGuidance,
    owner:x.ownerRole,
    deadline:report.operatorActions.find(a=>a.controlId===x.id)?.dueBy??
      report.nextReviewBy,
    critical:x.importance==="CRITICAL",
    requiresProviderProof:x.category==="EXTERNAL_PROOF"||
      x.missingEvidence.some(s=>/provider|readback|external/i.test(s)),
  })).sort((a,b)=>Number(b.critical)-Number(a.critical)||
    a.deadline.localeCompare(b.deadline)||a.id.localeCompare(b.id));
  return {
    schema:"cyberpilot.incident.assurance.work-packet.v1",
    incidentId:report.incidentId,
    organizationId:report.organizationId,
    evaluatedAt:report.evaluatedAt,
    categories:groups,prioritization:priorities,
    humanSignoffConditions:[
      "Confirm current organization membership and scope",
      "Reconcile any unknown or partial source coverage",
      "Obtain independent approval for high-impact actions",
      "Distinguish offline training status from live incident response",
      "Require independently observed provider post-action verification",
      "Verify residual risks before marking an incident contained",
    ],outstandingCount:priorities.length,
    externalExecutionEnabled:false,
    clientSecurityImprovementVerified:false,
  };
}
export type AssuranceEscalation = {
  id:string;incidentId:string;organizationId:string;
  controlId:string;severity:"P0"|"P1"|"P2";
  rationale:string;dueAt:string;ownerRole:string;
  requiredEvidence:string[];suggestedAction:string;
  status:"PROPOSED_NOT_DISPATCHED";
  externalNotificationSent:false;
};
export function buildAssuranceEscalationPlan(report:AssuranceReport) {
  const open=report.controls.filter(x=>x.state!=="PASS_OFFLINE"&&
    x.state!=="NOT_APPLICABLE");
  const entries:AssuranceEscalation[]=open.map(x=>({
    id:"ESCALATION:"+x.id,incidentId:report.incidentId,
    organizationId:report.organizationId,
    controlId:x.id,
    severity:x.importance==="CRITICAL"?"P0":
      x.importance==="HIGH"?"P1":"P2",
    rationale:x.reason,
    dueAt:report.operatorActions.find(a=>
      a.controlId===x.id)?.dueBy??report.nextReviewBy,
    ownerRole:x.ownerRole,
    requiredEvidence:x.missingEvidence,
    suggestedAction:x.remediationGuidance,
    status:"PROPOSED_NOT_DISPATCHED",
    externalNotificationSent:false,
  }));
  const score={P0:3,P1:2,P2:1};
  entries.sort((a,b)=>score[b.severity]-score[a.severity]||
    a.dueAt.localeCompare(b.dueAt)||a.id.localeCompare(b.id));
  return {
    schema:"cyberpilot.incident.assurance.escalations.v1" as const,
    organizationId:report.organizationId,incidentId:report.incidentId,
    escalations:entries,criticalCount:entries.filter(x=>x.severity==="P0").length,
    overdueCount:entries.filter(x=>x.dueAt<report.evaluatedAt).length,
    autoDispatchDisabled:true as const,notificationsSent:0 as const,
    providerWrites:0 as const,
  };
}
export type AssuranceTrendSummary = {
  schema: "cyberpilot.incident.assurance.trend.v1";
  organizationId:string;incidentId:string;
  firstAt:string;lastAt:string;records:number;
  riskScores:number[];reportDigests:string[];
  currentUnknown:number;previousUnknown:number;
  deltaFromFirst:number;
  newlyBlockedControls:string[];
  resolvedOfflineControls:string[];
  noLongerObservedControls:string[];
  missingSourceHistory:boolean;
  complianceCertificationIssued:false;
  customerSecurityRiskReductionProven:false;
};
export function buildAssuranceTrend(
  reports:readonly AssuranceReport[],
):AssuranceTrendSummary {
  if(!reports.length||reports.length>100)
    throw Error("ASSURANCE_TREND_LENGTH_INVALID");
  const ordered=[...reports].sort((a,b)=>
    a.evaluatedAt.localeCompare(b.evaluatedAt));
  const org=ordered[0]!.organizationId,id=ordered[0]!.incidentId;
  if(ordered.some(x=>x.organizationId!==org||x.incidentId!==id||
      x.policyId!==ordered[0]!.policyId))
    throw Error("ASSURANCE_TREND_SCOPE_INVALID");
  const first=ordered[0]!,last=ordered[ordered.length-1]!;
  const compared=compareAssuranceReports(first,last);
  const previous=new Map(first.controls.map(x=>[x.id,x]));
  const current=new Map(last.controls.map(x=>[x.id,x]));
  const newlyBlockedControls=[...current.values()].filter(x=>
    x.state==="FAIL" && previous.get(x.id)?.state!=="FAIL").map(x=>x.id);
  const resolvedOfflineControls=[...current.values()].filter(x=>
    x.state==="PASS_OFFLINE"&&
    previous.has(x.id)&&previous.get(x.id)!.state!=="PASS_OFFLINE")
    .map(x=>x.id);
  return {
    schema:"cyberpilot.incident.assurance.trend.v1",
    organizationId:org,incidentId:id,
    firstAt:first.evaluatedAt,lastAt:last.evaluatedAt,
    records:ordered.length,
    riskScores:ordered.map(x=>x.riskScore),
    reportDigests:ordered.map(x=>x.integrityDigest),
    currentUnknown:last.unknownControls,
    previousUnknown:first.unknownControls,
    deltaFromFirst:last.riskScore-first.riskScore,
    newlyBlockedControls,resolvedOfflineControls,
    noLongerObservedControls:compared.retiredControls,
    missingSourceHistory:ordered.some(x=>x.sourceCoverage!=="EXPLICIT_SCOPE_ONLY"),
    complianceCertificationIssued:false,
    customerSecurityRiskReductionProven:false,
  };
}
function csv(value:unknown){
  const raw=String(value??"");
  return '"'+(/^[=+\-@\t\r]/.test(raw)?"'"+raw:raw)
    .replaceAll('"','""').replaceAll("\r"," ")
    .replaceAll("\n"," ")+'"';
}
export function exportAssuranceDossier(
  report:AssuranceReport,format:"JSON"|"CSV"|"MARKDOWN",
){
  const packet=prepareAssuranceWorkPacket(report);
  const escalation=buildAssuranceEscalationPlan(report);
  const manifest={
    schema:"cyberpilot.incident.assurance.dossier.v1",
    report,packet,escalation,
    signoffRequested:false,signoffGranted:false,
    providerWrites:0,externalSecurityImprovementVerified:false,
  };
  const digest=createHash("sha256")
    .update(JSON.stringify(manifest)).digest("hex");
  const filename="incident-assurance-"+report.incidentId;
  if(format==="JSON")return{
    filename:filename+".json",mime:"application/json",digest,
    content:JSON.stringify({...manifest,digest},null,2),
  };
  if(format==="CSV"){
    const rows=[["controlId","category","importance","state",
      "ownerRole","missingEvidence","dueBy"],
      ...report.controls.map(x=>[
        x.id,x.category,x.importance,x.state,x.ownerRole,
        x.missingEvidence.join(";"),
        report.operatorActions.find(a=>a.controlId===x.id)?.dueBy??"",
      ])];
    return{
      filename:filename+".csv",mime:"text/csv",digest,
      content:rows.map(x=>x.map(csv).join(",")).join("\r\n"),
    };
  }
  if(format!=="MARKDOWN")throw Error("ASSURANCE_EXPORT_FORMAT_INVALID");
  const safe=(x:string)=>x.replaceAll("|","\\|")
    .replaceAll("<","&lt;").replaceAll(">","&gt;");
  return{
    filename:filename+".md",mime:"text/markdown",digest,
    content:[
      "# CyberPilot incident assurance dossier",
      "Organization: "+report.organizationId,
      "Incident: "+report.incidentId,
      "Policy: "+report.policyId,
      "Status: "+report.status,
      "Risk band: "+report.riskBand,
      "Offline controls passed: "+report.passedOffline,
      "Unknown controls: "+report.unknownControls,
      "Actual provider containment verified: NO",
      "Digest: "+digest,"",
      "## Control register",
      "| Control | Outcome | Importance |",
      "|---|---|---|",
      ...report.controls.map(x=>"| "+x.id+" | "+x.state+" | "+x.importance+" |"),
      "","## Operator work",
      ...packet.prioritization.map(x=>"- "+safe(x.action)+
        " / "+safe(x.owner)+" / "+x.deadline),
      "","## Security limitations",
      "Training and workflow evidence do not establish LIVE containment.",
      "No external notifications or remediation commands were sent.",
    ].join("\n"),
  };
}
