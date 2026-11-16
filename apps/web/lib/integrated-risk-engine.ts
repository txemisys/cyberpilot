import { createHash } from "node:crypto";

/**
 * Cross-source, read-only risk intelligence. This deliberately consumes
 * existing persisted records without upgrading DECLARED or SYNTHETIC
 * evidence to an observed customer security control.
 */
export type IntegratedEvidenceSource = "MICROSOFT_365" | "GOOGLE_WORKSPACE" |
  "LAB" | "BASELINE" | "ASSETS" | "EXPOSURE" | "UNKNOWN";
export type IntegratedEvidenceState = "OBSERVED" | "DECLARED" |
  "UNKNOWN" | "ERROR" | "STALE";
export type IntegratedRiskSeverity = "CRITICAL" | "HIGH" | "MEDIUM" |
  "LOW" | "INFO" | "UNKNOWN";
export type IntegratedEvidenceInput = {
  id: string; organizationId: string; source: string; domain: string;
  controlId: string; state: string; scope: string; observedAt: string | null;
  createdAt: string; details: unknown;
};
export type IntegratedFindingInput = {
  id: string; organizationId: string; ruleId: string;
  key: string; severity: string; status: string; title: string;
  description: string; lastSeenAt: string; evidence: unknown;
};
export type IntegratedV2Input = {
  id: string; organizationId: string; snapshotId: string;
  modelId: string; modelRevision: number; status: string;
  score: number | null; coveragePercent: number; sourceClass: string;
  evaluatedAt: string; reportDigest: string;
  manifestDigest: string; verifiedControls: number; totalControls: number;
};
export type IntegratedDeclaredActionInput = {
  id: string; organizationId: string; questionId: string;
  sourceDraftRevision: number; status: string; revision: number;
  dueAt: string | null; ownerUserId: string | null; updatedAt: string;
};
export type IntegratedRiskInput = {
  organizationId: string; evaluatedAt: string;
  evidence: IntegratedEvidenceInput[];
  findings: IntegratedFindingInput[];
  assessments: IntegratedV2Input[];
  declaredActions: IntegratedDeclaredActionInput[];
  countOfRecords: {
    evidence: number; findings: number;
    assessments: number; declaredActions: number;
  };
  sourceLimits: {
    evidence: number; findings: number;
    assessments: number; declaredActions: number;
  };
};
export type IntegratedRiskIssue = {
  code: string; level: "BLOCK" | "WARNING";
  recordIds: string[]; description: string;
};
export type IntegratedControlRow = {
  id: string; domain: string; controlId: string; scope: string;
  sources: IntegratedEvidenceSource[];
  observed: number; declared: number; unknown: number;
  errors: number; stale: number; distinctEvidence: number;
  currentState: "OBSERVED_WITH_LIMITS" | "DECLARED_ONLY" |
    "UNKNOWN" | "ERROR" | "CONFLICT" | "STALE";
  earliestObservationAt: string | null;
  latestObservationAt: string | null;
  evidenceIds: string[];
  hasContradictoryStates: boolean;
  remotelyAuthenticated: false;
  independentlyVerifiedSecure: false;
};
export type IntegratedRiskRow = {
  key: string; organizationId: string;
  domain: string; scope: string; controlId: string;
  severity: IntegratedRiskSeverity;
  rank: number; status: "OPEN" | "RESOLVED" | "UNKNOWN";
  title: string; description: string;
  source: IntegratedEvidenceSource;
  sourceFindingIds: string[];
  sourceEvidenceIds: string[];
  observedAt: string | null;
  confidence: "DECLARED_OR_UNVERIFIED" | "SOURCE_REPORTED" | "UNKNOWN";
  evidenceState: IntegratedControlRow["currentState"];
  uncertainty: string[];
  actionNeeded: boolean;
  deduplicatedFindingCount: number;
  proofOfRemediation: false;
};
export type IntegratedRiskDigest = {
  schema: "cyberpilot.integrated.risks.v1";
  organizationId: string; evaluatedAt: string;
  state: "REVIEW_REQUIRED" | "INCOMPLETE" | "NO_PERSISTED_EVIDENCE";
  counts: {
    evidence: number; controls: number; findings: number;
    openFindings: number; resolvedFindings: number;
    actionableRisks: number; deduplicated: number;
    declaredActions: number; overdueDeclaredActions: number;
    unassignedDeclaredActions: number;
    unknownControls: number; staleControls: number;
    conflictControls: number; syntheticAssessments: number;
    authenticatedLiveAssessments: number;
  };
  coverage: {
    persistedRecordsComplete: boolean;
    scopedToOrganization: boolean;
    sourceFamilies: IntegratedEvidenceSource[];
    controlDomains: string[];
    missingCoverageIsHealthy: false;
    allSourcesAuthenticated: false;
    fullRiskAssessmentCertified: false;
  };
  latestAssessment: {
    snapshotId: string; modelId: string; revision: number;
    coveragePercent: number; numericScore: number | null;
    scoreVisibleAsCustomerHealth: false;
    sourceClass: string; evaluatedAt: string;
    reportDigest: string; verifiedControls: number;
    totalControls: number;
  } | null;
  controls: IntegratedControlRow[];
  risks: IntegratedRiskRow[];
  issues: IntegratedRiskIssue[];
  limitations: string[];
  customerConsentInferred: false;
  historicalV1ScoreModified: false;
  remediationAutomaticallyExecuted: false;
  evidenceSecurityCertified: false;
  digest: string;
};
const knownSources: readonly IntegratedEvidenceSource[] = [
  "MICROSOFT_365","GOOGLE_WORKSPACE","LAB",
  "BASELINE","ASSETS","EXPOSURE","UNKNOWN",
];
const knownStates: readonly IntegratedEvidenceState[] = [
  "OBSERVED","DECLARED","UNKNOWN","ERROR","STALE",
];
const ranks: Record<IntegratedRiskSeverity,number> = {
  CRITICAL: 0,HIGH:1,MEDIUM:2,LOW:3,INFO:4,UNKNOWN:5,
};
const exactIso = (s: string | null): boolean =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const safeId = (s: string): boolean =>
  typeof s === "string" && s.length >= 1 && s.length <= 200 &&
  !/[\u0000-\u001f\u007f]/.test(s);
const clean = (s: string,max=500): string =>
  typeof s === "string" ? s.replace(/[\u0000-\u001f\u007f]/g," ")
    .slice(0,max).trim() : "";
function canonical(x: unknown): string {
  if (x === null) return "null";
  if (typeof x === "string" || typeof x === "boolean")
    return JSON.stringify(x);
  if (typeof x === "number") {
    if (!Number.isFinite(x)) throw Error("Non-finite input");
    return JSON.stringify(x);
  }
  if (Array.isArray(x)) return "[" + x.map(canonical).join(",") + "]";
  if (typeof x === "object") return "{" + Object.entries(x)
    .sort(([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>JSON.stringify(k)+":"+canonical(v)).join(",")+"}";
  throw Error("Non-canonical risk field");
}
const hash = (value: unknown) =>
  createHash("sha256").update(canonical(value)).digest("hex");
const uniq = <T>(xs: readonly T[]): T[] => [...new Set(xs)];
function source(value: string): IntegratedEvidenceSource {
  return knownSources.includes(value as IntegratedEvidenceSource) ?
    value as IntegratedEvidenceSource : "UNKNOWN";
}
function severity(value: string): IntegratedRiskSeverity {
  return Object.hasOwn(ranks,value) ?
    value as IntegratedRiskSeverity : "UNKNOWN";
}
function state(value: string): IntegratedEvidenceState {
  return knownStates.includes(value as IntegratedEvidenceState) ?
    value as IntegratedEvidenceState : "UNKNOWN";
}
function controlIdentity(domain: string, control: string, scope: string) {
  return hash([domain,control,scope]);
}
function issue(code: string, level: IntegratedRiskIssue["level"],
  description: string, ids: string[] = []): IntegratedRiskIssue {
  return {code,level,description,recordIds:uniq(ids).sort().slice(0,200)};
}
function bounded(input: IntegratedRiskInput) {
  return (Object.keys(input.countOfRecords) as Array<
    keyof IntegratedRiskInput["countOfRecords"]>).every(k =>
      Number.isSafeInteger(input.countOfRecords[k]) &&
      input.countOfRecords[k] >= 0 &&
      input.countOfRecords[k] <= input.sourceLimits[k]);
}
function recordScope(input: IntegratedRiskInput): string[] {
  const bad: string[] = [];
  const scan = (records: Array<{organizationId:string;id:string}>)=>{
    for(const r of records)
      if(r.organizationId!==input.organizationId || !safeId(r.id))
        bad.push(r.id);
  };
  scan(input.evidence); scan(input.findings);
  scan(input.assessments); scan(input.declaredActions);
  return uniq(bad);
}
function normalizeControls(input:IntegratedRiskInput,
  issues:IntegratedRiskIssue[]): IntegratedControlRow[] {
  const groups = new Map<string,IntegratedEvidenceInput[]>();
  for(const item of input.evidence) {
    const key=controlIdentity(item.domain,item.controlId,item.scope);
    groups.set(key,[...(groups.get(key)??[]),item]);
    if(!safeId(item.controlId)||!safeId(item.domain)||!safeId(item.scope))
      issues.push(issue("EVIDENCE_FIELDS_INVALID","BLOCK",
        "Evidence control identity is incomplete.",[item.id]));
    if(item.observedAt!==null&&!exactIso(item.observedAt))
      issues.push(issue("EVIDENCE_TIME_INVALID","BLOCK",
        "Observation timestamp is invalid.",[item.id]));
  }
  const controls:IntegratedControlRow[]=[];
  for(const [key,items] of groups){
    const first=items[0]!;
    const variants=uniq(items.map(x=>state(x.state)));
    const observed=items.filter(x=>state(x.state)==="OBSERVED");
    const declared=items.filter(x=>state(x.state)==="DECLARED");
    const unknown=items.filter(x=>state(x.state)==="UNKNOWN");
    const errors=items.filter(x=>state(x.state)==="ERROR");
    const stale=items.filter(x=>state(x.state)==="STALE"||
      (x.observedAt!==null && exactIso(x.observedAt) &&
        Date.parse(input.evaluatedAt)-Date.parse(x.observedAt)>
          90*86400000));
    const conflict=observed.length>0 &&
      (declared.length>0 || errors.length>0 ||
        unknown.length>0);
    const observations=items.map(x=>x.observedAt)
      .filter((x):x is string=>x!==null&&exactIso(x)).sort();
    const current:IntegratedControlRow["currentState"] =
      conflict?"CONFLICT":errors.length?"ERROR":
      stale.length?"STALE":
      observed.length?"OBSERVED_WITH_LIMITS":
      declared.length?"DECLARED_ONLY":"UNKNOWN";
    controls.push({
      id:key,domain:clean(first.domain,80),
      controlId:clean(first.controlId,140),
      scope:clean(first.scope,180),
      sources:uniq(items.map(x=>source(x.source))).sort(),
      observed:observed.length,declared:declared.length,
      unknown:unknown.length,errors:errors.length,
      stale:stale.length,distinctEvidence:items.length,
      currentState:current,
      earliestObservationAt:observations[0]??null,
      latestObservationAt:observations.at(-1)??null,
      evidenceIds:uniq(items.map(x=>x.id)).sort(),
      hasContradictoryStates:conflict,
      remotelyAuthenticated:false,
      independentlyVerifiedSecure:false,
    });
    if(conflict) issues.push(issue("EVIDENCE_SOURCE_CONFLICT","WARNING",
      "Different persisted states refer to the same control and scope.",
      items.map(x=>x.id)));
    if(stale.length) issues.push(issue("EVIDENCE_STALE","WARNING",
      "Evidence is old or explicitly stale.",stale.map(x=>x.id)));
  }
  return controls.sort((a,b)=>a.domain.localeCompare(b.domain)||
    a.controlId.localeCompare(b.controlId)||a.scope.localeCompare(b.scope));
}
function fingerprintFinding(item:IntegratedFindingInput) {
  const value=[item.ruleId.trim().toLowerCase(),
    clean(item.title,250).toLowerCase()];
  // Do not merge findings merely because severity matches.
  return hash(value);
}
function riskRows(input:IntegratedRiskInput,
  controls:IntegratedControlRow[],issues:IntegratedRiskIssue[]):
  IntegratedRiskRow[] {
  const groups=new Map<string,IntegratedFindingInput[]>();
  for(const finding of input.findings){
    if(!safeId(finding.ruleId)||!safeId(finding.key))
      issues.push(issue("FINDING_IDENTITY_INVALID","BLOCK",
        "Finding identity is incomplete.",[finding.id]));
    if(!exactIso(finding.lastSeenAt))
      issues.push(issue("FINDING_TIMESTAMP_INVALID","BLOCK",
        "Finding last-seen timestamp is invalid.",[finding.id]));
    const key=fingerprintFinding(finding);
    groups.set(key,[...(groups.get(key)??[]),finding]);
  }
  const rows:IntegratedRiskRow[]=[];
  for(const [key,items] of groups) {
    const active=items.filter(x=>x.status==="OPEN");
    const sample=active[0]??items[0]!;
    const severitySelected=items.map(x=>severity(x.severity))
      .sort((a,b)=>ranks[a]-ranks[b])[0]??"UNKNOWN";
    const related=controls.filter(x=>
      x.controlId===sample.ruleId ||
      x.controlId.toLowerCase()===sample.ruleId.toLowerCase());
    const relevant=related[0];
    const uncertain:string[]=[];
    if(!related.length) uncertain.push("NO_LINKED_CONTROL_EVIDENCE");
    if(related.some(x=>x.currentState!=="OBSERVED_WITH_LIMITS"))
      uncertain.push("INCOMPLETE_OR_UNVERIFIED_EVIDENCE");
    if(related.some(x=>x.hasContradictoryStates))
      uncertain.push("CONFLICTING_SOURCE_STATES");
    if(items.some(x=>x.status!=="OPEN"&&x.status!=="RESOLVED"))
      uncertain.push("UNRECOGNIZED_FINDING_STATUS");
    if(active.length>0&&items.some(x=>x.status==="RESOLVED"))
      uncertain.push("MIXED_RESOLUTION_STATE");
    const links=uniq(related.flatMap(x=>x.evidenceIds)).sort();
    const newest=items.map(x=>x.lastSeenAt)
      .filter(exactIso).sort().at(-1)??null;
    rows.push({
      key,organizationId:input.organizationId,
      domain:relevant?.domain??"UNMAPPED",
      scope:relevant?.scope??"UNVERIFIED",
      controlId:sample.ruleId,
      severity:severitySelected,rank:ranks[severitySelected],
      status:active.length?"OPEN":
        items.every(x=>x.status==="RESOLVED")?"RESOLVED":"UNKNOWN",
      title:clean(sample.title,250),
      description:clean(sample.description,2000),
      source:related.length===1?related[0]!.sources[0]??"UNKNOWN":"UNKNOWN",
      sourceFindingIds:uniq(items.map(x=>x.id)).sort(),
      sourceEvidenceIds:links,
      observedAt:newest,
      confidence:links.length===0?"UNKNOWN":
        related.every(x=>x.currentState==="OBSERVED_WITH_LIMITS")?
          "SOURCE_REPORTED":"DECLARED_OR_UNVERIFIED",
      evidenceState:relevant?.currentState??"UNKNOWN",
      uncertainty:uniq(uncertain),
      actionNeeded:active.length>0,
      deduplicatedFindingCount:items.length,
      proofOfRemediation:false,
    });
  }
  return rows.sort((a,b)=>a.status===b.status?
    a.rank-b.rank||a.title.localeCompare(b.title) :
    a.status==="OPEN"?-1:b.status==="OPEN"?1:
      a.status==="UNKNOWN"?-1:1);
}
function latestAssessment(input:IntegratedRiskInput) {
  const ordered=[...input.assessments].sort((a,b)=>
    b.evaluatedAt.localeCompare(a.evaluatedAt)||
      b.id.localeCompare(a.id));
  const item=ordered[0];
  if(!item) return null;
  return {
    snapshotId:item.snapshotId,modelId:item.modelId,
    revision:item.modelRevision,
    coveragePercent:item.coveragePercent,
    numericScore:item.score,
    scoreVisibleAsCustomerHealth:false as const,
    sourceClass:item.sourceClass,
    evaluatedAt:item.evaluatedAt,
    reportDigest:item.reportDigest,
    verifiedControls:item.verifiedControls,
    totalControls:item.totalControls,
  };
}
export function buildIntegratedRiskDigest(input:IntegratedRiskInput):
  IntegratedRiskDigest {
  if(!safeId(input.organizationId)||!exactIso(input.evaluatedAt))
    throw Error("Invalid scope or assessment clock.");
  const issues:IntegratedRiskIssue[]=[];
  const complete=bounded(input);
  if(!complete)issues.push(issue("DATABASE_QUERY_TRUNCATED","BLOCK",
    "At least one source collection exceeds its bounded limit."));
  const bad=recordScope(input);
  if(bad.length)issues.push(issue("CROSS_ORGANIZATION_SOURCE","BLOCK",
    "Foreign or malformed source IDs present.",bad));
  const evidenceIds=input.evidence.map(x=>x.id);
  if(new Set(evidenceIds).size!==evidenceIds.length)
    issues.push(issue("DUPLICATE_EVIDENCE_ROWS","BLOCK",
      "Evidence IDs are repeated within one report."));
  const snapshotIds=input.assessments.map(x=>x.snapshotId);
  if(new Set(snapshotIds).size!==snapshotIds.length)
    issues.push(issue("DUPLICATE_ASSESSMENTS","BLOCK",
      "Assessment snapshots must be unique."));
  const controls=normalizeControls(input,issues);
  const risks=riskRows(input,controls,issues);
  const assessment=latestAssessment(input);
  const sourceFamilies=uniq(input.evidence.map(x=>source(x.source))).sort();
  const domains=uniq(input.evidence.map(x=>clean(x.domain,80))).sort();
  const overdue=input.declaredActions.filter(x=>
    x.dueAt!==null&&exactIso(x.dueAt)&&
    x.dueAt<input.evaluatedAt&&
    x.status!=="COMPLETED_REPORTED");
  const synthetic=input.assessments.filter(x=>
    /SYNTHETIC|OFFLINE|LAB/.test(x.sourceClass));
  const authenticated=input.assessments.filter(x=>
    x.sourceClass==="AUTHENTICATED_LIVE");
  if(authenticated.length>0)
    issues.push(issue("LIVE_PROVENANCE_NOT_REVALIDATED","WARNING",
      "A stored sourceClass label is not independent tenant authentication.",
      authenticated.map(x=>x.id)));
  const base={
    schema:"cyberpilot.integrated.risks.v1" as const,
    organizationId:input.organizationId,evaluatedAt:input.evaluatedAt,
    state:(!complete||bad.length||issues.some(x=>x.level==="BLOCK")?
      "INCOMPLETE":input.evidence.length===0&&input.findings.length===0?
      "NO_PERSISTED_EVIDENCE":"REVIEW_REQUIRED") as
      IntegratedRiskDigest["state"],
    counts:{
      evidence:input.evidence.length,
      controls:controls.length,
      findings:input.findings.length,
      openFindings:input.findings.filter(x=>x.status==="OPEN").length,
      resolvedFindings:input.findings.filter(x=>x.status==="RESOLVED").length,
      actionableRisks:risks.filter(x=>x.actionNeeded).length,
      deduplicated:Math.max(0,input.findings.length-risks.length),
      declaredActions:input.declaredActions.length,
      overdueDeclaredActions:overdue.length,
      unassignedDeclaredActions:input.declaredActions.filter(x=>
        x.ownerUserId===null).length,
      unknownControls:controls.filter(x=>x.currentState==="UNKNOWN").length,
      staleControls:controls.filter(x=>x.currentState==="STALE").length,
      conflictControls:controls.filter(x=>x.hasContradictoryStates).length,
      syntheticAssessments:synthetic.length,
      authenticatedLiveAssessments:authenticated.length,
    },
    coverage:{
      persistedRecordsComplete:complete,
      scopedToOrganization:bad.length===0,
      sourceFamilies,controlDomains:domains,
      missingCoverageIsHealthy:false as const,
      allSourcesAuthenticated:false as const,
      fullRiskAssessmentCertified:false as const,
    },
    latestAssessment:assessment,
    controls,risks,issues,
    limitations:[
      "Only persisted tenant-scoped records are reconciled.",
      "No LIVE provider is contacted by the integrated read model.",
      "Declared and synthetic observations never imply verified security.",
      "A stored LIVE source label alone does not authenticate the tenant.",
      "Missing coverage, partial observations and expired evidence are not healthy.",
      "A merged finding is not proof that the risk was remediated.",
      "Historical CyberScore v1 and migration state remain unchanged.",
      "No customer approval, independent remediation or certification is inferred.",
    ],
    customerConsentInferred:false as const,
    historicalV1ScoreModified:false as const,
    remediationAutomaticallyExecuted:false as const,
    evidenceSecurityCertified:false as const,
  };
  return {...base,digest:hash(base)};
}
export function verifyIntegratedRiskDigest(report:IntegratedRiskDigest,
  organizationId?:string):{valid:boolean;errors:string[]} {
  const errors:string[]=[];
  const {digest,...base}=report;
  if(hash(base)!==digest)errors.push("DIGEST_MISMATCH");
  if(organizationId&&organizationId!==report.organizationId)
    errors.push("TENANT_MISMATCH");
  if(report.customerConsentInferred!==false||
    report.historicalV1ScoreModified!==false||
    report.remediationAutomaticallyExecuted!==false||
    report.evidenceSecurityCertified!==false)
    errors.push("FORBIDDEN_SECURITY_ASSERTION");
  if(report.coverage.allSourcesAuthenticated!==false||
    report.coverage.fullRiskAssessmentCertified!==false||
    report.coverage.missingCoverageIsHealthy!==false)
    errors.push("COVERAGE_OVERCLAIM");
  if(report.risks.some(x=>x.proofOfRemediation!==false))
    errors.push("REMEDIATION_OVERCLAIM");
  return {valid:errors.length===0,errors};
}
export function compareIntegratedRiskDigests(
  earlier:IntegratedRiskDigest,later:IntegratedRiskDigest) {
  if(!verifyIntegratedRiskDigest(earlier).valid||
    !verifyIntegratedRiskDigest(later).valid||
    earlier.organizationId!==later.organizationId||
    earlier.evaluatedAt>=later.evaluatedAt)
    throw Error("Invalid cross-tenant or nonchronological comparison.");
  const before=new Map(earlier.risks.map(x=>[x.key,x]));
  const after=new Map(later.risks.map(x=>[x.key,x]));
  return {
    organizationId:later.organizationId,
    earlierDigest:earlier.digest,laterDigest:later.digest,
    added:later.risks.filter(x=>!before.has(x.key)).map(x=>x.key),
    absent:earlier.risks.filter(x=>!after.has(x.key)).map(x=>x.key),
    newlyOpen:later.risks.filter(x=>x.status==="OPEN"&&
      before.get(x.key)?.status!=="OPEN").map(x=>x.key),
    noLongerOpen:earlier.risks.filter(x=>x.status==="OPEN"&&
      after.get(x.key)?.status!=="OPEN").map(x=>x.key),
    evidenceCountDelta:later.counts.evidence-earlier.counts.evidence,
    coverageNotAutomaticallyProven:true as const,
    verifiedRiskReduction:false as const,
    v1ScoreComparable:false as const,
  };
}
export function exportIntegratedRiskDigest(report:IntegratedRiskDigest,
  format:"JSON"|"CSV"|"MARKDOWN") {
  if(!verifyIntegratedRiskDigest(report).valid)
    throw Error("Cannot export altered risk digest.");
  const stem="integrated-risk-"+report.evaluatedAt.slice(0,10);
  if(format==="JSON")return{
    filename:stem+".json",mime:"application/json",
    content:JSON.stringify(report,null,2)};
  const quote=(x:string|number)=>
    '"'+String(x).replaceAll('"','""')+'"';
  if(format==="CSV")return{
    filename:stem+".csv",mime:"text/csv",
    content:[
      "key,severity,status,title,confidence,evidenceState,sourceFindingIds",
      ...report.risks.map(x=>[
        x.key,x.severity,x.status,x.title,x.confidence,
        x.evidenceState,x.sourceFindingIds.join(";"),
      ].map(quote).join(",")),
    ].join("\n"),
  };
  if(format!=="MARKDOWN")throw Error("Invalid risk export format.");
  return{
    filename:stem+".md",mime:"text/markdown",
    content:[
      "# Integrated security risk register",
      "",
      "Organization: "+report.organizationId,
      "As of: "+report.evaluatedAt,
      "State: "+report.state,
      "Digest: "+report.digest,
      "",
      ...report.risks.map(x=>
        "## "+x.severity+" — "+x.title+"\n"+
        "State: "+x.status+"; confidence: "+x.confidence+
        "; findings: "+x.sourceFindingIds.length+"\n"+
        "Evidence: "+x.evidenceState+"\n"+
        "Scope: "+x.scope+"\n"),
      "",
      ...report.limitations.map(x=>"- "+x),
    ].join("\n"),
  };
}
