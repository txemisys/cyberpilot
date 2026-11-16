import {createHash} from "node:crypto";
import type {
  IntegratedRiskDigest,IntegratedRiskRow,IntegratedControlRow,
  IntegratedEvidenceSource,
} from "./integrated-risk-engine";
import {verifyIntegratedRiskDigest} from "./integrated-risk-engine";
import type {
  ActionSnapshot,ActionBoardSummary,
} from "./integrated-action-domain";
import {summarizeIntegratedActionBoard,
  validateActionSnapshot} from "./integrated-action-domain";

/**
 * Versioned executive cockpit, limited to the organization's existing
 * PostgreSQL records. It NEVER promotes source labels or raw score
 * numbers to proof of a customer's security posture.
 */
export type ExecutiveCockpitInput={
  organizationId:string;
  generatedAt:string;
  reportId:string;
  riskDigest:IntegratedRiskDigest;
  actions:ActionSnapshot[];
  auditIssues:string[];
  actionsTruncated:boolean;
  includeResolved:boolean;
};
export type ExecutiveCockpitSection={
  id:"OVERVIEW"|"COVERAGE"|"RISKS"|"ACTIONS"|
    "DEADLINES"|"EXCEPTIONS"|"PROVENANCE"|"LIMITATIONS";
  title:string;
  state:"REQUIRES_ATTENTION"|"INCOMPLETE"|"INFORMATIONAL";
  narrative:string;
  total:number;uncertain:number;critical:number;
  sourceReferences:string[];
  cannotInferCompliance:true;
};
export type ExecutiveCockpitRisk={
  riskKey:string;title:string;severity:string;
  status:string;domain:string;source:IntegratedEvidenceSource;
  priorityRank:number;
  evidenceCount:number;sourceFindingCount:number;
  uncertainty:string[];
  ownerUserId:string|null;
  actionId:string|null;
  actionState:string|null;
  actionRevision:number|null;
  lastObservedAt:string|null;
  dueAt:string|null;
  isOverdue:boolean;
  actionCompletedReported:boolean;
  externallyRemediated:false;
  needsReview:boolean;
};
export type ExecutiveCockpitCoverage={
  domain:string;controls:number;
  observedWithLimits:number;
  declaredOnly:number;unknown:number;stale:number;
  conflicting:number;errors:number;
  observedPercent:number;
  independentlyVerifiedPercent:null;
  healthyStatusPermitted:false;
  missingCoverageDoesNotImplySafety:true;
};
export type ExecutiveCockpitTrendInput={
  previous:ExecutiveCockpitReport;
  current:ExecutiveCockpitReport;
};
export type ExecutiveCockpitReport={
  schema:"cyberpilot.executive.cockpit.v1";
  organizationId:string;generatedAt:string;reportId:string;
  verdict:"NO_PERSISTED_EVIDENCE"|"INCOMPLETE"|"REQUIRES_REVIEW";
  riskDigest:string;
  summary:{
    sourceFamilies:number;
    sourceEvidenceCount:number;
    controlScopes:number;
    findingRecords:number;
    openRisks:number;
    highPriorityOpenRisks:number;
    uncertainRisks:number;
    duplicateFindingRows:number;
    unresolvedWithoutActions:number;
    actionsTotal:number;
    overdueActions:number;
    unassignedActions:number;
    blockedActions:number;
    reportedCompletedActions:number;
    declaredExceptions:number;
    expiredExceptions:number;
    auditIssues:number;
    syntheticSnapshots:number;
    liveSourceLabelsUnverified:number;
    v2Score:number|null;
    v2ScoreInterpretation:"STORED_OPTIONAL_NOT_CERTIFIED";
    v1ScoreUnchanged:true;
  };
  coverage:ExecutiveCockpitCoverage[];
  risks:ExecutiveCockpitRisk[];
  sections:ExecutiveCockpitSection[];
  actionSummary:ActionBoardSummary;
  audit:{
    riskSourceComplete:boolean;
    actionsSourceComplete:boolean;
    riskTenantBound:boolean;
    actionTenantBound:boolean;
    duplicateActionKeys:string[];
    staleSourceIdentifiers:string[];
    crossOrganizationRows:string[];
    actionAuditIssues:string[];
    canPassDevelopmentTraceability:boolean;
    passedUnconditionally:false;
  };
  provenance:{
    persistedRiskDigest:string;
    riskSnapshotTimestamp:string;
    latestOptionalV2SnapshotId:string|null;
    latestOptionalV2ModelRevision:number|null;
    latestOptionalV2SourceClass:string|null;
    latestOptionalV2ReportDigest:string|null;
    declaredEvidenceCount:number;
    syntheticSnapshotCount:number;
    externalProviderContacted:false;
    customerTenantAuthenticatedByThisReport:false;
  };
  caveats:string[];
  externalProviderCalls:0;
  customerCertificationGranted:false;
  technicalRemediationExecuted:false;
  independentCustomerApprovalProven:false;
  historicalCyberScoreRewritten:false;
  digest:string;
};
const iso=(s:string):boolean=>typeof s==="string"&&
  Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
const hash=(s:string)=>createHash("sha256").update(s).digest("hex");
function canon(x:unknown):string{
  if(x===null)return"null";
  if(typeof x==="boolean"||typeof x==="string")
    return JSON.stringify(x);
  if(typeof x==="number"){
    if(!Number.isFinite(x))throw Error("Nonfinite report field");
    return JSON.stringify(x);
  }
  if(Array.isArray(x))return"["+x.map(canon).join(",")+"]";
  if(typeof x==="object")return"{"+Object.entries(x).sort(
    ([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>JSON.stringify(k)+":"+canon(v)).join(",")+"}";
  throw Error("Report requires canonical JSON");
}
const digest=(x:unknown)=>hash(canon(x));
const uniq=<T>(xs:readonly T[]):T[]=>[...new Set(xs)];
function validate(input:ExecutiveCockpitInput){
  const issues:string[]=[];
  if(!iso(input.generatedAt)||!input.reportId||
    input.reportId.length>128||
    input.organizationId!==input.riskDigest.organizationId||
    !verifyIntegratedRiskDigest(
      input.riskDigest,input.organizationId).valid)
    issues.push("INVALID_OR_CROSS_TENANT_RISK_DIGEST");
  if(input.actions.length>500)
    issues.push("ACTION_LIMIT_EXCEEDED");
  for(const action of input.actions)
    if(action.organizationId!==input.organizationId||
      !validateActionSnapshot(action).valid)
      issues.push("FOREIGN_OR_INVALID_ACTION");
  return uniq(issues);
}
function mappedCoverage(controls:IntegratedControlRow[]):
  ExecutiveCockpitCoverage[]{
  const domains=uniq(controls.map(x=>x.domain)).sort();
  return domains.map(domain=>{
    const rows=controls.filter(x=>x.domain===domain);
    const count=(state:IntegratedControlRow["currentState"])=>
      rows.filter(x=>x.currentState===state).length;
    const observed=count("OBSERVED_WITH_LIMITS");
    return{
      domain,controls:rows.length,
      observedWithLimits:observed,
      declaredOnly:count("DECLARED_ONLY"),
      unknown:count("UNKNOWN"),
      stale:count("STALE"),conflicting:count("CONFLICT"),
      errors:count("ERROR"),
      observedPercent:rows.length?
        Math.round(observed*100/rows.length):0,
      independentlyVerifiedPercent:null,
      healthyStatusPermitted:false,
      missingCoverageDoesNotImplySafety:true,
    };
  });
}
function linkRisks(risks:IntegratedRiskRow[],actions:ActionSnapshot[],
  asOf:string,includeResolved:boolean):ExecutiveCockpitRisk[]{
  const byKey=new Map(actions.map(x=>[x.riskKey,x]));
  return risks.filter(r=>includeResolved||r.status==="OPEN")
    .map(r=>{
      const action=byKey.get(r.key);
      const overdue=Boolean(action?.dueAt&&action.dueAt<asOf&&
        !["DONE_REPORTED","EXCEPTION"].includes(action.status));
      return{
        riskKey:r.key,title:r.title,severity:r.severity,status:r.status,
        domain:r.domain,source:r.source,priorityRank:r.rank,
        evidenceCount:r.sourceEvidenceIds.length,
        sourceFindingCount:r.sourceFindingIds.length,
        uncertainty:[...r.uncertainty],
        ownerUserId:action?.ownerUserId??null,
        actionId:action?.actionId??null,
        actionState:action?.status??null,
        actionRevision:action?.revision??null,
        lastObservedAt:r.observedAt,
        dueAt:action?.dueAt??null,
        isOverdue:overdue,
        actionCompletedReported:action?.status==="DONE_REPORTED",
        externallyRemediated:false,
        needsReview:r.status==="OPEN"||r.uncertainty.length>0,
      };
    }).sort((a,b)=>a.priorityRank-b.priorityRank||
      Number(b.needsReview)-Number(a.needsReview)||
      a.title.localeCompare(b.title));
}
function createSection(
  id:ExecutiveCockpitSection["id"],title:string,
  narrative:string,total:number,uncertain:number,
  critical:number,ids:string[],
):ExecutiveCockpitSection{
  return{
    id,title,narrative,total,uncertain,critical,
    sourceReferences:uniq(ids).sort().slice(0,100),
    state:uncertain>0?"INCOMPLETE":
      critical>0?"REQUIRES_ATTENTION":"INFORMATIONAL",
    cannotInferCompliance:true,
  };
}
function coverageSection(input:ExecutiveCockpitInput,
  coverage:ExecutiveCockpitCoverage[]):ExecutiveCockpitSection{
  return createSection("COVERAGE","Cobertura de fuentes",
    "La cantidad de registros no prueba que se haya observado el perímetro.",
    coverage.length,coverage.reduce((n,x)=>n+x.unknown+
      x.stale+x.errors+x.conflicting+x.declaredOnly,0),
    0,coverage.map(x=>x.domain));
}
function riskSection(risks:ExecutiveCockpitRisk[]):ExecutiveCockpitSection{
  return createSection("RISKS","Riesgos priorizados",
    "Los hallazgos correlacionados requieren validación humana y de contexto.",
    risks.length,risks.filter(x=>x.uncertainty.length>0).length,
    risks.filter(x=>x.status==="OPEN"&&
      ["CRITICAL","HIGH"].includes(x.severity)).length,
    risks.map(x=>x.riskKey));
}
function actionSection(actions:ActionSnapshot[],
  summary:ActionBoardSummary):ExecutiveCockpitSection{
  return createSection("ACTIONS","Acciones y responsables",
    "DONE_REPORTED es una declaración, nunca verificación técnica.",
    summary.total,summary.unassigned+summary.blocked,
    summary.urgent,actions.map(x=>x.actionId));
}
function deadlineSection(actions:ActionSnapshot[],
  summary:ActionBoardSummary,asOf:string):ExecutiveCockpitSection{
  return createSection("DEADLINES","Vencimientos y escalado",
    "Las acciones vencidas no deben desaparecer por falta de evidencias.",
    actions.filter(x=>x.dueAt!==null).length,
    summary.overdue,summary.overdue,
    actions.filter(x=>x.dueAt!==null&&x.dueAt<asOf&&
      x.status!=="DONE_REPORTED").map(x=>x.actionId));
}
function exceptionSection(actions:ActionSnapshot[],
  summary:ActionBoardSummary):ExecutiveCockpitSection{
  return createSection("EXCEPTIONS","Excepciones temporales",
    "Una excepción registrada no es aceptación legal del riesgo.",
    summary.exceptions,summary.expiredExceptions,
    summary.expiredExceptions,
    actions.filter(x=>x.status==="EXCEPTION").map(x=>x.actionId));
}
function provenanceSection(input:ExecutiveCockpitInput,
  invalid:string[]):ExecutiveCockpitSection{
  return createSection("PROVENANCE","Procedencia y auditoría",
    "Sin firmas del cliente, autenticación LIVE o certificación implícita.",
    input.riskDigest.counts.evidence,
    invalid.length+input.auditIssues.length,
    invalid.length,
    [...invalid,...input.auditIssues]);
}
export function buildExecutiveCockpit(
  input:ExecutiveCockpitInput):ExecutiveCockpitReport{
  const errors=validate(input);
  const risk=input.riskDigest;
  const actions=input.actions;
  const summary=summarizeIntegratedActionBoard(actions,input.generatedAt);
  const coverage=mappedCoverage(risk.controls);
  const rows=linkRisks(risk.risks,actions,input.generatedAt,
    input.includeResolved);
  const duplicateKeys=actions.filter((x,i)=>
    actions.findIndex(y=>y.riskKey===x.riskKey)!==i).map(x=>x.riskKey);
  const knownKeys=new Set(risk.risks.map(x=>x.key));
  const staleIdentifiers=actions.filter(x=>!knownKeys.has(x.riskKey))
    .map(x=>x.actionId);
  const crossOrg=actions.filter(x=>x.organizationId!==
    input.organizationId).map(x=>x.actionId);
  const open=rows.filter(x=>x.status==="OPEN");
  const untracked=open.filter(x=>x.actionId===null);
  const uncertain=open.filter(x=>x.uncertainty.length>0);
  const high=open.filter(x=>["HIGH","CRITICAL"].includes(x.severity));
  const problems=uniq([...errors,...input.auditIssues,
    ...(duplicateKeys.length?["DUPLICATE_ACTION_RISK_KEYS"]:[]),
    ...(staleIdentifiers.length?["ACTION_SOURCE_NOT_IN_REGISTRY"]:[])]);
  const sections:ExecutiveCockpitSection[]=[
    createSection("OVERVIEW","Resumen de la pyme",
      "Vista de gestión sin conexiones externas ni calificación de cumplimiento.",
      risk.counts.findings,uncertain.length,high.length,
      open.map(x=>x.riskKey)),
    coverageSection(input,coverage),
    riskSection(rows),actionSection(actions,summary),
    deadlineSection(actions,summary,input.generatedAt),
    exceptionSection(actions,summary),
    provenanceSection(input,problems),
    createSection("LIMITATIONS","Límites de evaluación",
      "No se ha validado legalmente ningún tenant ni comprobado remediación.",
      8,0,0,[]),
  ];
  const incomplete=problems.length>0||
    risk.state==="INCOMPLETE"||
    input.actionsTruncated||
    !risk.coverage.persistedRecordsComplete;
  const base={
    schema:"cyberpilot.executive.cockpit.v1" as const,
    organizationId:input.organizationId,
    generatedAt:input.generatedAt,reportId:input.reportId,
    verdict:(risk.state==="NO_PERSISTED_EVIDENCE"&&actions.length===0?
      "NO_PERSISTED_EVIDENCE":incomplete?
      "INCOMPLETE":"REQUIRES_REVIEW") as
      ExecutiveCockpitReport["verdict"],
    riskDigest:risk.digest,
    summary:{
      sourceFamilies:risk.coverage.sourceFamilies.length,
      sourceEvidenceCount:risk.counts.evidence,
      controlScopes:risk.counts.controls,
      findingRecords:risk.counts.findings,
      openRisks:open.length,
      highPriorityOpenRisks:high.length,
      uncertainRisks:uncertain.length,
      duplicateFindingRows:risk.counts.deduplicated,
      unresolvedWithoutActions:untracked.length,
      actionsTotal:summary.total,
      overdueActions:summary.overdue,
      unassignedActions:summary.unassigned,
      blockedActions:summary.blocked,
      reportedCompletedActions:summary.doneReported,
      declaredExceptions:summary.exceptions,
      expiredExceptions:summary.expiredExceptions,
      auditIssues:problems.length,
      syntheticSnapshots:risk.counts.syntheticAssessments,
      liveSourceLabelsUnverified:
        risk.counts.authenticatedLiveAssessments,
      v2Score:risk.latestAssessment?.numericScore??null,
      v2ScoreInterpretation:"STORED_OPTIONAL_NOT_CERTIFIED" as const,
      v1ScoreUnchanged:true as const,
    },
    coverage,risks:rows,sections,actionSummary:summary,
    audit:{
      riskSourceComplete:risk.coverage.persistedRecordsComplete,
      actionsSourceComplete:!input.actionsTruncated,
      riskTenantBound:risk.coverage.scopedToOrganization,
      actionTenantBound:crossOrg.length===0,
      duplicateActionKeys:uniq(duplicateKeys),
      staleSourceIdentifiers:uniq(staleIdentifiers),
      crossOrganizationRows:uniq(crossOrg),
      actionAuditIssues:problems,
      canPassDevelopmentTraceability:!incomplete,
      passedUnconditionally:false as const,
    },
    provenance:{
      persistedRiskDigest:risk.digest,
      riskSnapshotTimestamp:risk.evaluatedAt,
      latestOptionalV2SnapshotId:
        risk.latestAssessment?.snapshotId??null,
      latestOptionalV2ModelRevision:
        risk.latestAssessment?.revision??null,
      latestOptionalV2SourceClass:
        risk.latestAssessment?.sourceClass??null,
      latestOptionalV2ReportDigest:
        risk.latestAssessment?.reportDigest??null,
      declaredEvidenceCount:risk.controls.reduce((n,x)=>n+x.declared,0),
      syntheticSnapshotCount:risk.counts.syntheticAssessments,
      externalProviderContacted:false as const,
      customerTenantAuthenticatedByThisReport:false as const,
    },
    caveats:[
      "This dashboard reads tenant-scoped persisted records only.",
      "Synthetic/LAB v2 scores never count as verified customer posture.",
      "A stored sourceClass label cannot prove external authentication.",
      "DECLARED, UNKNOWN, ERROR and STALE are not healthy observations.",
      "A report can contain both resolved and open findings from different times.",
      "A reported completed action has not been independently remediated.",
      "Exception acceptance is a local workflow, not legal approval.",
      "CyberScore v1 remains unchanged and cannot be directly compared to v2.",
      "No LIVE connector, scanning, certification, or customer acceptance occurs.",
      "SHA-256 integrity is not a digital signature or external attestation.",
    ],
    externalProviderCalls:0 as const,
    customerCertificationGranted:false as const,
    technicalRemediationExecuted:false as const,
    independentCustomerApprovalProven:false as const,
    historicalCyberScoreRewritten:false as const,
  };
  return {...base,digest:digest(base)};
}
export function verifyExecutiveCockpit(
  report:ExecutiveCockpitReport,organizationId?:string
):{valid:boolean;errors:string[]}{
  const errors:string[]=[];
  const {digest:stored,...base}=report;
  if(digest(base)!==stored)errors.push("EXECUTIVE_DIGEST_INVALID");
  if(organizationId&&organizationId!==report.organizationId)
    errors.push("EXECUTIVE_FOREIGN_ORGANIZATION");
  if(report.externalProviderCalls!==0||
    report.customerCertificationGranted!==false||
    report.technicalRemediationExecuted!==false||
    report.independentCustomerApprovalProven!==false||
    report.historicalCyberScoreRewritten!==false)
    errors.push("EXECUTIVE_FALSE_SECURITY_CLAIM");
  if(report.summary.v1ScoreUnchanged!==true||
    report.summary.v2ScoreInterpretation!==
      "STORED_OPTIONAL_NOT_CERTIFIED")
    errors.push("CROSS_VERSION_SCORE_OVERCLAIM");
  if(report.risks.some(x=>x.externallyRemediated!==false))
    errors.push("FALSE_REMEDIATION_PROVENANCE");
  if(report.coverage.some(x=>x.healthyStatusPermitted!==false||
    x.independentlyVerifiedPercent!==null))
    errors.push("COVERAGE_SECURITY_OVERCLAIM");
  if(report.verdict!=="INCOMPLETE"&&
    (report.audit.actionAuditIssues.length>0||
      !report.audit.riskSourceComplete||
      !report.audit.actionsSourceComplete))
    errors.push("INCOMPLETE_ASSESSMENT_OVERSTATED");
  return{valid:errors.length===0,errors};
}
export function compareExecutiveCockpits(
  before:ExecutiveCockpitReport,after:ExecutiveCockpitReport){
  if(!verifyExecutiveCockpit(before).valid||
    !verifyExecutiveCockpit(after).valid||
    before.organizationId!==after.organizationId||
    before.generatedAt>=after.generatedAt)
    throw Error("Invalid comparison of executive snapshots");
  const oldKeys=new Set(before.risks.map(x=>x.riskKey));
  const nextKeys=new Set(after.risks.map(x=>x.riskKey));
  const previous=new Map(before.risks.map(x=>[x.riskKey,x]));
  return{
    organizationId:after.organizationId,
    previousDigest:before.digest,currentDigest:after.digest,
    introducedRisks:after.risks.filter(x=>!oldKeys.has(x.riskKey))
      .map(x=>x.riskKey),
    absentRisks:before.risks.filter(x=>!nextKeys.has(x.riskKey))
      .map(x=>x.riskKey),
    newOverdue:after.risks.filter(x=>x.isOverdue&&
      !previous.get(x.riskKey)?.isOverdue).map(x=>x.riskKey),
    newActionAssignments:after.risks.filter(x=>
      x.actionId!==null&&
      previous.get(x.riskKey)?.actionId===null).map(x=>x.riskKey),
    unresolvedDelta:after.summary.unresolvedWithoutActions-
      before.summary.unresolvedWithoutActions,
    evidenceDelta:after.summary.sourceEvidenceCount-
      before.summary.sourceEvidenceCount,
    reportedCompletionsDelta:after.summary.reportedCompletedActions-
      before.summary.reportedCompletedActions,
    actualRiskReductionEstablished:false as const,
    crossVersionScoreComparisonPermitted:false as const,
    legallyApprovedExceptionInferred:false as const,
  };
}
export function exportExecutiveCockpit(
  report:ExecutiveCockpitReport,
  format:"JSON"|"CSV"|"MARKDOWN"){
  if(!verifyExecutiveCockpit(report).valid)
    throw Error("Cannot export tampered executive snapshot");
  const filename="cyberpilot-executive-"+report.generatedAt.slice(0,10);
  if(format==="JSON")return{
    filename:filename+".json",mime:"application/json",
    content:JSON.stringify(report,null,2),
  };
  const quote=(value:string|number|null)=>
    '"'+String(value??"").replaceAll('"','""')+'"';
  if(format==="CSV")return{
    filename:filename+".csv",mime:"text/csv",
    content:[
      "riskKey,severity,status,title,domain,source,owner,actionState,overdue,uncertain",
      ...report.risks.map(x=>[
        x.riskKey,x.severity,x.status,x.title,x.domain,x.source,
        x.ownerUserId,x.actionState,String(x.isOverdue),
        x.uncertainty.join(";"),
      ].map(quote).join(",")),
    ].join("\n"),
  };
  if(format!=="MARKDOWN")throw Error("Unsupported executive format");
  return{
    filename:filename+".md",mime:"text/markdown",
    content:[
      "# CyberPilot — Executive security follow-up",
      "",
      "Organization: "+report.organizationId,
      "Generated: "+report.generatedAt,
      "Verdict: "+report.verdict,
      "Report digest: "+report.digest,
      "",
      "## Summary",
      "- Open risks: "+report.summary.openRisks,
      "- High priority: "+report.summary.highPriorityOpenRisks,
      "- Without follow-up: "+report.summary.unresolvedWithoutActions,
      "- Overdue actions: "+report.summary.overdueActions,
      "- Declared completed actions: "+
        report.summary.reportedCompletedActions,
      "- Unverified source labels: "+
        report.summary.liveSourceLabelsUnverified,
      "",
      "## Coverage",
      ...report.coverage.map(x=>
        "- "+x.domain+": "+x.observedWithLimits+
        " source observations, "+x.declaredOnly+" declarations, "+
        x.unknown+" unknown, "+x.stale+" stale"),
      "",
      "## Open risks",
      ...report.risks.filter(x=>x.status==="OPEN").map(x=>
        "- "+x.severity+" "+x.title+" ["+x.domain+"]"+
        " — "+(x.actionState??"NO ACTION")+
        (x.isOverdue?" (OVERDUE)":"")),
      "",
      "## Limitations",
      ...report.caveats.map(x=>"- "+x),
    ].join("\n"),
  };
}
