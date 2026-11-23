import { createHash } from "node:crypto";
import { type IncidentSnapshot, type IncidentEvent,
  incidentDigest } from "./incident-case-domain";
import { evaluateIncidentTriage,
  buildIncidentTriageBoard, type TriageBoard,
  type IncidentTriageItem } from "./incident-triage-assurance";
import { auditIncidentTimeline, reviewIncidentApprovals,
  planIncidentFollowUps } from "./incident-triage-timeline";
export type TriageCaseDossier = {
  schema:"cyberpilot.incident.triage.dossier.v1";
  organizationId:string;incidentId:string;preparedAt:string;
  snapshotDigest:string;eventAuditDigest:string;
  item:IncidentTriageItem;
  audit:ReturnType<typeof auditIncidentTimeline>;
  approvalReview:ReturnType<typeof reviewIncidentApprovals>;
  followUps:ReturnType<typeof planIncidentFollowUps>;
  reviewDecision:"BLOCKED"|"NEEDS_EVIDENCE"|"READY_FOR_HUMAN_REVIEW";
  warnings:string[];evidenceCoverage:number;staleProofCount:number;
  manualActionCount:number;
  deliveredNotifications:0;providerWrites:0;
  customerSecurityImprovementVerified:false;
};
export function buildTriageCaseDossier(s:IncidentSnapshot,
  events:IncidentEvent[],at:string,truncated=false):TriageCaseDossier{
  const item=evaluateIncidentTriage(s,at);
  const audit=auditIncidentTimeline(s,events,truncated);
  const approvalReview=reviewIncidentApprovals(s,at);
  const followUps=planIncidentFollowUps(s,at);
  const warnings=[
    ...audit.problems.map(p=>"AUDIT_"+p.code),
    ...item.blockers,
    ...approvalReview.reviewItems.filter(x=>x.humanReviewRequired)
      .map(x=>"APPROVAL_REVIEW_"+x.stepId),
  ];
  const reviewDecision: TriageCaseDossier["reviewDecision"]=
    !audit.complete||warnings.some(x=>x.startsWith("AUDIT_"))?
      "BLOCKED":item.missingProofCategories>0||
      item.stepsReportedNotVerified>0||approvalReview.selfApprovalRisks>0?
      "NEEDS_EVIDENCE":"READY_FOR_HUMAN_REVIEW";
  const evidenceCoverage=item.stageReviews.length?
    item.stageReviews.filter(x=>x.missingSources.length===0).length/
      item.stageReviews.length:0;
  return {schema:"cyberpilot.incident.triage.dossier.v1",
    organizationId:s.organizationId,incidentId:s.id,preparedAt:at,
    snapshotDigest:incidentDigest(s),
    eventAuditDigest:audit.chronologyDigest,
    item,audit,approvalReview,followUps,reviewDecision,warnings,
    evidenceCoverage,staleProofCount:item.staleEvidenceCount,
    manualActionCount:followUps.length,
    deliveredNotifications:0,providerWrites:0,
    customerSecurityImprovementVerified:false};
}
export type IncidentTriageTrend = {
  schema:"cyberpilot.incident.triage.trend.v1";
  organizationId:string;sampleCount:number;
  earlyAt:string;lateAt:string;
  addedCases:string[];removedCases:string[];
  urgencyIncreased:string[];urgencyReduced:string[];
  newlyOverdue:string[];noLongerOverdue:string[];
  evidenceGapsIncreased:string[];evidenceGapsReduced:string[];
  approvalsExpired:string[];newOwnerAssignments:string[];
  comparable:boolean;truncated:boolean;
  cybersecurityImprovementProven:false;
};
export function compareIncidentTriageBoards(earlier:TriageBoard,
  later:TriageBoard):IncidentTriageTrend{
  if(earlier.organizationId!==later.organizationId||
    earlier.generatedAt>later.generatedAt)
    throw Error("TRIAGE_TREND_TENANT_OR_TIME_INVALID");
  const before=new Map(earlier.items.map(x=>[x.id,x]));
  const after=new Map(later.items.map(x=>[x.id,x]));
  const common=later.items.filter(x=>before.has(x.id));
  return {schema:"cyberpilot.incident.triage.trend.v1",
    organizationId:earlier.organizationId,
    sampleCount:common.length,earlyAt:earlier.generatedAt,
    lateAt:later.generatedAt,
    addedCases:[...after.keys()].filter(x=>!before.has(x)),
    removedCases:[...before.keys()].filter(x=>!after.has(x)),
    urgencyIncreased:common.filter(x=>
      x.urgencyWeight>before.get(x.id)!.urgencyWeight).map(x=>x.id),
    urgencyReduced:common.filter(x=>
      x.urgencyWeight<before.get(x.id)!.urgencyWeight).map(x=>x.id),
    newlyOverdue:common.filter(x=>x.overdueByMinutes>0&&
      before.get(x.id)!.overdueByMinutes===0).map(x=>x.id),
    noLongerOverdue:common.filter(x=>x.overdueByMinutes===0&&
      before.get(x.id)!.overdueByMinutes>0).map(x=>x.id),
    evidenceGapsIncreased:common.filter(x=>x.missingProofCategories>
      before.get(x.id)!.missingProofCategories).map(x=>x.id),
    evidenceGapsReduced:common.filter(x=>x.missingProofCategories<
      before.get(x.id)!.missingProofCategories).map(x=>x.id),
    approvalsExpired:common.filter(x=>x.approvalExpiryCount>
      before.get(x.id)!.approvalExpiryCount).map(x=>x.id),
    newOwnerAssignments:common.filter(x=>x.ownerUserId!==null&&
      before.get(x.id)!.ownerUserId===null).map(x=>x.id),
    comparable:!earlier.truncated&&!later.truncated&&
      earlier.policyDigest===later.policyDigest,
    truncated:earlier.truncated||later.truncated,
    cybersecurityImprovementProven:false};
}
function safeCsv(v:unknown){
  const value=String(v??"");
  const safe=/^[=+\-@\t\r]/.test(value)?"'"+value:value;
  return '"'+safe.replaceAll('"','""').replaceAll("\r"," ")
    .replaceAll("\n"," ")+'"';
}
const sha=(content:string)=>createHash("sha256").update(content).digest("hex");
export function exportTriageBoard(board:TriageBoard,
  format:"JSON"|"CSV"|"MARKDOWN"){
  if(board.items.some(x=>x.organizationId!==board.organizationId))
    throw Error("TRIAGE_EXPORT_TENANT_INVALID");
  const basename="incident-triage-"+board.generatedAt.slice(0,10);
  if(format==="JSON"){
    const content=JSON.stringify(board,null,2);
    return {filename:basename+".json",mime:"application/json",
      content,digest:sha(content),externalDelivery:false};
  }
  if(format==="CSV"){
    const rows=[["incidentId","severity","urgency","state",
      "owner","overdueMinutes","missingSources","approvalIssues",
      "evidenceConflicts","nextReviewAt"],...board.items.map(x=>[
        x.id,x.severity,x.urgency,x.status,x.ownerUserId??"",
        String(x.overdueByMinutes),String(x.missingProofCategories),
        String(x.approvalExpiryCount),String(x.evidenceConflicts),
        x.reviewDueAt])];
    const content=rows.map(row=>row.map(safeCsv).join(",")).join("\r\n");
    return {filename:basename+".csv",mime:"text/csv",
      content,digest:sha(content),externalDelivery:false};
  }
  if(format==="MARKDOWN"){
    const clean=(x:string)=>x.replaceAll("|","\\|")
      .replaceAll("<","&lt;").replaceAll(">","&gt;");
    const content=[
      "# CyberPilot guided incident triage",
      "Organization: "+board.organizationId,
      "Reviewed: "+board.generatedAt,
      "Total: "+board.total+" (truncated: "+board.truncated+")",
      "Immediate: "+board.immediate,
      "Overdue: "+board.overdue,
      "Missing source coverage: "+board.evidenceGaps,
      "Containment provider verified: NO","",
      "| Case | Priority | Status | Overdue |",
      "|---|---|---|---|",
      ...board.items.map(x=>"| "+clean(x.title)+" | "+x.urgency+
        " | "+x.status+" | "+x.overdueByMinutes+" min |"),
      "","No provider operations were carried out by this report.",
    ].join("\n");
    return {filename:basename+".md",mime:"text/markdown",
      content,digest:sha(content),externalDelivery:false};
  }
  throw Error("TRIAGE_EXPORT_FORMAT_INVALID");
}
export function exportTriageDossier(d:TriageCaseDossier,
  format:"JSON"|"CSV"|"MARKDOWN"){
  const basename="incident-review-"+d.incidentId;
  if(format==="JSON"){
    const content=JSON.stringify(d,null,2);
    return {filename:basename+".json",mime:"application/json",
      content,digest:sha(content),externalDelivery:false};
  }
  if(format==="CSV"){
    const rows=[["stepId","status","risk","sourcesMissing","blockedBy"],
      ...d.item.stageReviews.map(x=>[
        x.stepId,x.status,x.risk,x.missingSources.join(";"),
        x.barriers.join(";")])];
    const content=rows.map(x=>x.map(safeCsv).join(",")).join("\r\n");
    return {filename:basename+".csv",mime:"text/csv",
      content,digest:sha(content),externalDelivery:false};
  }
  if(format==="MARKDOWN"){
    const clean=(x:string)=>x.replaceAll("|","\\|")
      .replaceAll("<","&lt;").replaceAll(">","&gt;");
    const content=["# Guided incident evidence review",
      "Incident: "+d.incidentId,"Organization: "+d.organizationId,
      "Review status: "+d.reviewDecision,
      "Audit chain complete: "+d.audit.complete,
      "Case checksum: "+d.snapshotDigest,
      "Evidence coverage: "+Math.round(d.evidenceCoverage*100)+"%",
      "Provider containment verified: NO","","## Open operator actions",
      ...d.followUps.map(x=>"- "+clean(x.code)+
        " (due "+x.dueAt+")"),
      "","## Critical missing evidence",
      ...d.item.stageReviews.filter(x=>x.missingSources.length)
        .map(x=>"- "+clean(x.stepId)+": "+x.missingSources.join(", ")),
      "","These local checks are not proof of external remediation."].join("\n");
    return {filename:basename+".md",mime:"text/markdown",
      content,digest:sha(content),externalDelivery:false};
  }
  throw Error("TRIAGE_DOSSIER_FORMAT_INVALID");
}
