import {createHash} from "node:crypto";
import type {IntegratedRiskDigest,IntegratedControlRow,IntegratedRiskRow,
  IntegratedEvidenceSource} from "./integrated-risk-engine";
import {verifyIntegratedRiskDigest} from "./integrated-risk-engine";

/**
 * A deterministic evidence-review queue for an offline, tenant-scoped SME.
 * Neither a source label nor a manually closed finding is authentication
 * or proof of the absence of risk.
 */
export type EvidenceDecisionCode =
  "QUARANTINE"|"REQUEST_TECHNICAL_PROOF"|"REQUEST_SCOPE_PROOF"|
  "RECONCILE_CONFLICT"|"REFRESH_STALE"|"REVIEW_ERROR"|
  "REVIEW_OPEN_RISK"|"REVIEW_REPORTED_RESOLUTION"|
  "REVIEW_DECLARATION"|"MONITOR_UNCERTAINTY";
export type EvidenceDecisionPriority="P0"|"P1"|"P2"|"P3";
export type EvidenceDecisionStatus=
  "BLOCKED"|"REQUIRES_REVIEW"|"FOLLOW_UP"|"MONITOR";
export type EvidenceDecision={
  key:string;organizationId:string;code:EvidenceDecisionCode;
  priority:EvidenceDecisionPriority;status:EvidenceDecisionStatus;
  domain:string;controlId:string;scope:string;
  source:IntegratedEvidenceSource[];
  description:string;recommendedAction:string;
  supportingEvidenceIds:string[];supportingFindingIds:string[];
  scoreContributionPermitted:false;
  customerRiskVerified:false;
  origin: "EVIDENCE"|"FINDING"|"REPORT_INTEGRITY";
  ageDays:number|null;
  dueDays:number;
  confidence:"UNKNOWN"|"SOURCE_REPORTED"|"DECLARED_OR_UNVERIFIED";
  blocksComplianceClaim:true;
};
export type EvidenceSourceQuality={
  source:IntegratedEvidenceSource;
  totalControls:number;
  observedWithLimits:number;declared:number;unknown:number;
  errors:number;stale:number;conflicted:number;
  evidenceReferences:number;
  assignedDecisions:number;
  unverifiedObservationCount:number;
  authenticatedCustomerScope:false;
  trustedSourceEquivalence:false;
};
export type EvidenceDomainQuality={
  domain:string;controls:number;findingCount:number;
  unresolvedFindingCount:number;unverifiedControls:number;
  staleControls:number;conflicts:number;errors:number;
  decisions:number;urgentDecisions:number;
  technicalProofRate:number|null;
  externallyAudited:false;
};
export type EvidenceDecisionReport={
  schema:"cyberpilot.evidence.decisions.v1";
  organizationId:string;evaluatedAt:string;
  riskDigest:string;
  outcome:"BLOCKED"|"REVIEW_REQUIRED"|"NO_DATA";
  decisions:EvidenceDecision[];
  sources:EvidenceSourceQuality[];
  domains:EvidenceDomainQuality[];
  totals:{
    decisions:number;priority0:number;priority1:number;
    priority2:number;priority3:number;blocked:number;
    needsTechnicalProof:number;needsScopeProof:number;
    conflictingControls:number;staleControls:number;
    unresolvedRisks:number;reportedResolutions:number;
    unknownControls:number;sourceErrors:number;
    decisionsWithoutEvidence:number;
  };
  qualityIssues:string[];
  operatorWorkflowOnly:true;
  externalTenantAuthenticated:false;
  automaticallyResolvedFindings:false;
  complianceCertified:false;
  historicalV1ScoreChanged:false;
  reportDigest:string;
};
export type EvidenceDecisionFilter={
  priority?:EvidenceDecisionPriority[];
  codes?:EvidenceDecisionCode[];
  domain?:string;source?:IntegratedEvidenceSource;
  includeMonitors?:boolean;search?:string;
  offset?:number;limit?:number;
};
export type EvidenceDecisionPage={
  organizationId:string;total:number;offset:number;limit:number;
  nextOffset:number|null;items:EvidenceDecision[];
  filtersApplied:EvidenceDecisionFilter;
  noDataIsHealthy:false;
};
const ISO=(s:string)=>typeof s==="string"&&
  Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const sha=(x:string)=>createHash("sha256").update(x).digest("hex");
const priorities:EvidenceDecisionPriority[]=["P0","P1","P2","P3"];
const priorityRank=(p:EvidenceDecisionPriority)=>priorities.indexOf(p);
function safeText(s:string){return String(s).replace(/[\u0000-\u001f\u007f]/g," ").slice(0,300);}
function hashDecision(parts:string[]){return sha(parts.map(x=>x.length+":"+x).join("|"));}
function unique<T>(values:readonly T[]){return [...new Set(values)];}
function ageDays(last:string|null,asOf:string):number|null{
  if(!last||!ISO(last))return null;
  return Math.max(0,Math.floor(
    (Date.parse(asOf)-Date.parse(last))/86400000));
}
function priority(code:EvidenceDecisionCode,
  severity?:IntegratedRiskRow["severity"]):EvidenceDecisionPriority{
  if(code==="QUARANTINE"||code==="RECONCILE_CONFLICT")return"P0";
  if(code==="REVIEW_OPEN_RISK"&&
    (severity==="CRITICAL"||severity==="HIGH"))return"P0";
  if(["REFRESH_STALE","REVIEW_ERROR","REQUEST_SCOPE_PROOF"].includes(code))
    return"P1";
  if(code==="REVIEW_OPEN_RISK")return"P1";
  if(["REQUEST_TECHNICAL_PROOF","REVIEW_REPORTED_RESOLUTION",
    "REVIEW_DECLARATION"].includes(code))return"P2";
  return"P3";
}
function recommended(code:EvidenceDecisionCode):string{
  switch(code){
    case"QUARANTINE":
      return"Do not release this dataset; inspect its tenant and integrity provenance.";
    case"RECONCILE_CONFLICT":
      return"Compare scoped source records; record the contradiction without selecting a winner.";
    case"REFRESH_STALE":
      return"Request a new authorized observation; keep the previous record marked stale.";
    case"REVIEW_ERROR":
      return"Diagnose source collection error; do not replace ERROR with a passing result.";
    case"REQUEST_TECHNICAL_PROOF":
      return"Request technical evidence with authenticated scope, timestamps and source digest.";
    case"REQUEST_SCOPE_PROOF":
      return"Establish exact assets, users or domains included in the assessment.";
    case"REVIEW_OPEN_RISK":
      return"Triage the source finding, nominate an owner and agree the remediation plan.";
    case"REVIEW_REPORTED_RESOLUTION":
      return"Verify independently before treating the reported resolution as risk reduction.";
    case"REVIEW_DECLARATION":
      return"Record declaration provenance and request independent technical verification.";
    case"MONITOR_UNCERTAINTY":
      return"Keep this item explicitly unknown and reassess when evidence becomes available.";
  }
}
function description(code:EvidenceDecisionCode,ref:string):string{
  switch(code){
    case"QUARANTINE":return"Source integrity or organization boundary is not demonstrated: "+ref;
    case"REQUEST_TECHNICAL_PROOF":return"No authenticated technical assurance for "+ref;
    case"REQUEST_SCOPE_PROOF":return"Scope is not independently evidenced for "+ref;
    case"RECONCILE_CONFLICT":return"Contradictory states observed for "+ref;
    case"REFRESH_STALE":return"Stale or expired evidence for "+ref;
    case"REVIEW_ERROR":return"Source returned an error for "+ref;
    case"REVIEW_OPEN_RISK":return"Open source finding requiring management: "+ref;
    case"REVIEW_REPORTED_RESOLUTION":return"Reported closure without independent verification: "+ref;
    case"REVIEW_DECLARATION":return"Operator declaration cannot prove security for "+ref;
    case"MONITOR_UNCERTAINTY":return"Assessment remains incomplete for "+ref;
  }
}
function due(code:EvidenceDecisionCode,p:EvidenceDecisionPriority){
  if(code==="QUARANTINE")return 0;
  if(p==="P0")return 1;
  if(p==="P1")return 7;
  if(p==="P2")return 30;
  return 90;
}
function decision(input:{
  organizationId:string;code:EvidenceDecisionCode;ref:string;
  control?:IntegratedControlRow;risk?:IntegratedRiskRow;
  origin:EvidenceDecision["origin"];evaluatedAt:string;
}):EvidenceDecision{
  const control=input.control,risk=input.risk;
  const p=priority(input.code,risk?.severity);
  const sources=control?.sources??(risk?[risk.source]:["UNKNOWN"]);
  const scope=control?.scope??risk?.scope??"UNVERIFIED";
  const controlId=control?.controlId??risk?.controlId??"UNKNOWN";
  const domain=control?.domain??risk?.domain??"UNMAPPED";
  const supportingEvidenceIds=unique([
    ...(control?.evidenceIds??[]),...(risk?.sourceEvidenceIds??[]),
  ]).sort();
  const supportingFindingIds=unique(
    risk?.sourceFindingIds??[]).sort();
  return{
    key:hashDecision([input.organizationId,input.code,
      control?.id??risk?.key??input.ref]),
    organizationId:input.organizationId,
    code:input.code,priority:p,
    status:input.code==="QUARANTINE"?"BLOCKED":
      p==="P0"||p==="P1"?"REQUIRES_REVIEW":
      p==="P2"?"FOLLOW_UP":"MONITOR",
    origin:input.origin,domain,controlId,scope,
    source:unique(sources).sort(),
    description:safeText(description(input.code,input.ref)),
    recommendedAction:recommended(input.code),
    supportingEvidenceIds,supportingFindingIds,
    scoreContributionPermitted:false,customerRiskVerified:false,
    ageDays:ageDays(control?.latestObservationAt??
      risk?.observedAt??null,input.evaluatedAt),
    dueDays:due(input.code,p),
    confidence:risk?.confidence??"UNKNOWN",
    blocksComplianceClaim:true,
  };
}
function decisionsForControl(report:IntegratedRiskDigest,
  control:IntegratedControlRow):EvidenceDecision[]{
  const base={organizationId:report.organizationId,
    control,origin:"EVIDENCE" as const,
    evaluatedAt:report.evaluatedAt,
    ref:control.domain+":"+control.controlId+"@"+control.scope};
  const entries:EvidenceDecisionCode[]=[];
  if(control.hasContradictoryStates||
    control.currentState==="CONFLICT")entries.push("RECONCILE_CONFLICT");
  if(control.stale>0||control.currentState==="STALE")
    entries.push("REFRESH_STALE");
  if(control.errors>0||control.currentState==="ERROR")
    entries.push("REVIEW_ERROR");
  if(control.declared>0||control.currentState==="DECLARED_ONLY")
    entries.push("REVIEW_DECLARATION");
  if(control.unknown>0||control.currentState==="UNKNOWN")
    entries.push("MONITOR_UNCERTAINTY");
  if(!control.remotelyAuthenticated)
    entries.push("REQUEST_SCOPE_PROOF");
  if(!control.independentlyVerifiedSecure)
    entries.push("REQUEST_TECHNICAL_PROOF");
  return unique(entries).map(code=>decision({...base,code}));
}
function decisionsForFinding(report:IntegratedRiskDigest,
  finding:IntegratedRiskRow):EvidenceDecision[]{
  const base={organizationId:report.organizationId,
    risk:finding,origin:"FINDING" as const,
    evaluatedAt:report.evaluatedAt,
    ref:finding.title};
  const codes:EvidenceDecisionCode[]=[];
  if(finding.status==="OPEN")codes.push("REVIEW_OPEN_RISK");
  if(finding.status==="RESOLVED")
    codes.push("REVIEW_REPORTED_RESOLUTION");
  if(finding.status==="UNKNOWN"||finding.uncertainty.length>0)
    codes.push("MONITOR_UNCERTAINTY");
  if(finding.sourceEvidenceIds.length===0)
    codes.push("REQUEST_TECHNICAL_PROOF");
  return unique(codes).map(code=>decision({...base,code}));
}
function sourceQuality(report:IntegratedRiskDigest,
  decisions:EvidenceDecision[]):EvidenceSourceQuality[]{
  const allSources=unique([
    ...report.coverage.sourceFamilies,
    ...report.controls.flatMap(x=>x.sources),
  ]).sort();
  return allSources.map(source=>{
    const controls=report.controls.filter(x=>x.sources.includes(source));
    const count=(status:IntegratedControlRow["currentState"])=>
      controls.filter(x=>x.currentState===status).length;
    return{
      source,totalControls:controls.length,
      observedWithLimits:count("OBSERVED_WITH_LIMITS"),
      declared:count("DECLARED_ONLY"),
      unknown:count("UNKNOWN"),errors:count("ERROR"),
      stale:count("STALE"),conflicted:count("CONFLICT"),
      evidenceReferences:unique(controls.flatMap(x=>x.evidenceIds)).length,
      assignedDecisions:decisions.filter(x=>x.source.includes(source)).length,
      unverifiedObservationCount:controls.filter(x=>
        !x.independentlyVerifiedSecure).length,
      authenticatedCustomerScope:false,
      trustedSourceEquivalence:false,
    };
  });
}
function domainQuality(report:IntegratedRiskDigest,
  decisions:EvidenceDecision[]):EvidenceDomainQuality[]{
  const all=unique([
    ...report.coverage.controlDomains,
    ...report.risks.map(x=>x.domain),
  ]).sort();
  return all.map(domain=>{
    const controls=report.controls.filter(x=>x.domain===domain);
    const risks=report.risks.filter(x=>x.domain===domain);
    const local=decisions.filter(x=>x.domain===domain);
    return{
      domain,controls:controls.length,findingCount:risks.length,
      unresolvedFindingCount:risks.filter(x=>x.status==="OPEN").length,
      unverifiedControls:controls.filter(x=>
        !x.independentlyVerifiedSecure).length,
      staleControls:controls.filter(x=>x.stale>0).length,
      conflicts:controls.filter(x=>x.hasContradictoryStates).length,
      errors:controls.filter(x=>x.errors>0).length,
      decisions:local.length,
      urgentDecisions:local.filter(x=>x.priority==="P0").length,
      technicalProofRate:null,externallyAudited:false,
    };
  });
}
function canonical(value:unknown):string{
  if(value===null||typeof value==="string"||
    typeof value==="boolean"||typeof value==="number"){
    if(typeof value==="number"&&!Number.isFinite(value))
      throw Error("Nonfinite evidence quality field");
    return JSON.stringify(value);
  }
  if(Array.isArray(value))return"["+value.map(canonical).join(",")+"]";
  if(typeof value==="object")return"{"+Object.entries(value).sort(
    ([a],[b])=>a.localeCompare(b)).map(([k,v])=>
      JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
  throw Error("Non-canonical evidence quality field");
}
export function buildEvidenceDecisionReport(
  report:IntegratedRiskDigest):EvidenceDecisionReport{
  if(!verifyIntegratedRiskDigest(report).valid)
    throw Error("INVALID_INTEGRATED_RISK_REPORT");
  const issues=report.issues.filter(x=>x.level==="BLOCK");
  const integrityDecisions=issues.map(x=>decision({
    organizationId:report.organizationId,code:"QUARANTINE",
    ref:x.code,origin:"REPORT_INTEGRITY",evaluatedAt:report.evaluatedAt,
  }));
  const controls=report.controls.flatMap(x=>decisionsForControl(report,x));
  const findings=report.risks.flatMap(x=>decisionsForFinding(report,x));
  const decisions=[...integrityDecisions,...controls,...findings].sort(
    (a,b)=>priorityRank(a.priority)-priorityRank(b.priority)||
      a.domain.localeCompare(b.domain)||
      a.code.localeCompare(b.code)||a.key.localeCompare(b.key));
  const keys=decisions.map(x=>x.key);
  if(new Set(keys).size!==keys.length)
    throw Error("DUPLICATE_EVIDENCE_DECISION_ID");
  const sources=sourceQuality(report,decisions);
  const domains=domainQuality(report,decisions);
  const count=(priority:EvidenceDecisionPriority)=>
    decisions.filter(x=>x.priority===priority).length;
  const base={
    schema:"cyberpilot.evidence.decisions.v1" as const,
    organizationId:report.organizationId,evaluatedAt:report.evaluatedAt,
    riskDigest:report.digest,
    outcome:(issues.length||report.state==="INCOMPLETE"?"BLOCKED":
      report.state==="NO_PERSISTED_EVIDENCE"?"NO_DATA":
      "REVIEW_REQUIRED") as EvidenceDecisionReport["outcome"],
    decisions,sources,domains,
    totals:{
      decisions:decisions.length,
      priority0:count("P0"),priority1:count("P1"),
      priority2:count("P2"),priority3:count("P3"),
      blocked:integrityDecisions.length,
      needsTechnicalProof:decisions.filter(x=>
        x.code==="REQUEST_TECHNICAL_PROOF").length,
      needsScopeProof:decisions.filter(x=>
        x.code==="REQUEST_SCOPE_PROOF").length,
      conflictingControls:report.counts.conflictControls,
      staleControls:report.counts.staleControls,
      unresolvedRisks:report.risks.filter(x=>x.status==="OPEN").length,
      reportedResolutions:report.risks.filter(x=>
        x.status==="RESOLVED").length,
      unknownControls:report.counts.unknownControls,
      sourceErrors:report.controls.filter(x=>x.errors>0).length,
      decisionsWithoutEvidence:decisions.filter(x=>
        x.supportingEvidenceIds.length===0).length,
    },
    qualityIssues:unique(report.issues.map(x=>x.code)).sort(),
    operatorWorkflowOnly:true as const,
    externalTenantAuthenticated:false as const,
    automaticallyResolvedFindings:false as const,
    complianceCertified:false as const,
    historicalV1ScoreChanged:false as const,
  };
  return{...base,reportDigest:sha(canonical(base))};
}
export function verifyEvidenceDecisionReport(
  report:EvidenceDecisionReport,organizationId?:string){
  const errors:string[]=[];
  const{reportDigest,...base}=report;
  if(sha(canonical(base))!==reportDigest)
    errors.push("DIGEST_INTEGRITY_FAILED");
  if(organizationId&&organizationId!==report.organizationId)
    errors.push("TENANT_MISMATCH");
  if(report.complianceCertified!==false||
    report.automaticallyResolvedFindings!==false||
    report.externalTenantAuthenticated!==false||
    report.historicalV1ScoreChanged!==false)
    errors.push("FORBIDDEN_SECURITY_CLAIM");
  if(report.decisions.some(x=>
    x.organizationId!==report.organizationId||
    x.scoreContributionPermitted!==false||
    x.customerRiskVerified!==false||
    x.blocksComplianceClaim!==true))
    errors.push("DECISION_INTEGRITY_VIOLATION");
  return{valid:errors.length===0,errors};
}
export function filterEvidenceDecisions(
  report:EvidenceDecisionReport,filters:EvidenceDecisionFilter={}
):EvidenceDecisionPage{
  if(!verifyEvidenceDecisionReport(report).valid)
    throw Error("INVALID_EVIDENCE_DECISION_REPORT");
  const offset=filters.offset??0,limit=filters.limit??50;
  if(!Number.isSafeInteger(offset)||offset<0||
    !Number.isSafeInteger(limit)||limit<1||limit>200)
    throw Error("INVALID_DECISION_PAGE");
  const search=filters.search?.trim().toLowerCase()??"";
  const items=report.decisions.filter(x=>
    (!filters.priority||filters.priority.includes(x.priority))&&
    (!filters.codes||filters.codes.includes(x.code))&&
    (!filters.domain||x.domain===filters.domain)&&
    (!filters.source||x.source.includes(filters.source))&&
    (filters.includeMonitors!==false||x.status!=="MONITOR")&&
    (!search||[x.code,x.description,x.domain,x.controlId,x.scope,
      x.recommendedAction].join(" ").toLowerCase().includes(search)));
  return{
    organizationId:report.organizationId,
    total:items.length,offset,limit,
    nextOffset:offset+limit<items.length?offset+limit:null,
    items:items.slice(offset,offset+limit),
    filtersApplied:filters,noDataIsHealthy:false,
  };
}
export function compareEvidenceDecisionReports(
  before:EvidenceDecisionReport,after:EvidenceDecisionReport){
  if(!verifyEvidenceDecisionReport(before).valid||
    !verifyEvidenceDecisionReport(after).valid||
    before.organizationId!==after.organizationId||
    before.evaluatedAt>=after.evaluatedAt)
    throw Error("INVALID_EVIDENCE_QUALITY_COMPARISON");
  const previous=new Map(before.decisions.map(x=>[x.key,x]));
  const current=new Map(after.decisions.map(x=>[x.key,x]));
  const appeared=after.decisions.filter(x=>!previous.has(x.key));
  const disappeared=before.decisions.filter(x=>!current.has(x.key));
  const priorityChanged=after.decisions.filter(x=>
    previous.has(x.key)&&previous.get(x.key)!.priority!==x.priority);
  return{
    organizationId:after.organizationId,
    previousDigest:before.reportDigest,currentDigest:after.reportDigest,
    newDecisions:appeared.map(x=>x.key),
    absentDecisions:disappeared.map(x=>x.key),
    priorityChanges:priorityChanged.map(x=>({
      key:x.key,from:previous.get(x.key)!.priority,to:x.priority,
    })),
    urgentDelta:after.totals.priority0-before.totals.priority0,
    sourceErrorDelta:after.totals.sourceErrors-before.totals.sourceErrors,
    absentDecisionIndicatesRemediation:false as const,
    sourceCoverageCertified:false as const,
  };
}
export function exportEvidenceDecisions(
  report:EvidenceDecisionReport,format:"CSV"|"JSON"|"MARKDOWN"){
  if(!verifyEvidenceDecisionReport(report).valid)
    throw Error("DECISION_REPORT_TAMPERED");
  const stem="evidence-decisions-"+report.evaluatedAt.slice(0,10);
  if(format==="JSON")return{
    filename:stem+".json",mime:"application/json",
    content:JSON.stringify(report,null,2),
  };
  const q=(x:string|number|null)=>
    '"'+String(x??"").replaceAll('"','""')+'"';
  if(format==="CSV")return{
    filename:stem+".csv",mime:"text/csv",
    content:[
      "key,code,priority,domain,controlId,scope,description,action,evidenceIds",
      ...report.decisions.map(x=>[
        x.key,x.code,x.priority,x.domain,x.controlId,x.scope,
        x.description,x.recommendedAction,
        x.supportingEvidenceIds.join(";"),
      ].map(q).join(",")),
    ].join("\n"),
  };
  if(format!=="MARKDOWN")throw Error("UNKNOWN_DECISION_EXPORT");
  return{
    filename:stem+".md",mime:"text/markdown",
    content:[
      "# Evidence review and provenance",
      "Organization: "+report.organizationId,
      "Evaluated: "+report.evaluatedAt,
      "Outcome: "+report.outcome,
      "Digest: "+report.reportDigest,
      "",
      ...report.decisions.map(x=>
        "## "+x.priority+" "+x.code+" — "+x.controlId+"\n"+
        "Source: "+x.source.join(", ")+"\n"+
        "Scope: "+x.scope+"\n"+
        x.description+"\n"+x.recommendedAction+"\n"),
      "No customer certification, provider contact, or verified remediation.",
    ].join("\n"),
  };
}
