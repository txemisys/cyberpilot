import { createHash, timingSafeEqual } from "node:crypto";
import {
  CAPABILITIES, equalDigest,
  type GoogleDirectoryObservation, type GoogleCapability,
  type GoogleEvidenceRecord,
} from "./directory-contract";
import {
  assessGoogleWorkspace, verifyGoogleRiskAssessment,
  googleRemediationPlan, googleAssessmentManifest,
  type GoogleRiskAssessment,
} from "./risk-assessment";

export type WorkspaceReportSectionId =
  "EXECUTIVE" | "SCOPE" | "IDENTITIES" | "PRIVILEGES" |
  "MULTIFACTOR" | "DOMAINS" | "AUDIT" | "UNKNOWN" |
  "RECOMMENDATIONS" | "PROVENANCE" | "LIMITATIONS";
export type GoogleReportSection = {
  id: WorkspaceReportSectionId;
  title: string;
  state: "INFORMATIONAL" | "POTENTIAL_RISK" |
    "INCOMPLETE" | "NEEDS_REVIEW";
  headline: string;
  description: string;
  observedItems: number;
  potentialRisks: number;
  unknownItems: number;
  evidenceReferences: string[];
  nextActions: string[];
  customerApproved: false;
  completenessCertified: false;
};
export type GoogleReportFinding = {
  rank: number;
  rule: string;
  level: string;
  status: string;
  title: string;
  whyItMatters: string;
  suggestedAction: string;
  verification: string;
  sourceDigest: string;
  evidenceRefs: string[];
  humanChangeApprovalNeeded: true;
  autoActionExecuted: false;
  thirdPartyValidated: false;
};
export type WorkspaceCoverageSummary = {
  capability: GoogleCapability;
  state: string;
  sourceCount: number;
  observedCount: number;
  unknownCount: number;
  completeness: "VERIFIED_LOCAL_REFERENCE_ONLY" |
    "UNKNOWN" | "INCOMPLETE" | "UNAVAILABLE";
  confidence: "LOW" | "UNKNOWN";
  providerScopingLimitations: string[];
};
export type GoogleReportExport = {
  schema: "cyberpilot.google.executive.report.v1";
  organizationId: string;
  referenceTimestamp: string;
  assessmentSourceDigest: string;
  assessmentDigest: string;
  reportScope: "GOOGLE_WORKSPACE_OFFLINE_DEVELOPMENT";
  evidenceSourceClass: GoogleDirectoryObservation["source"];
  summary: {
    usersObserved: number;
    adminsObserved: number;
    domainRecords: number;
    auditEvents: number;
    potentialRisks: number;
    unresolvedUnknowns: number;
    incompleteCapabilities: number;
    previewScore: number | null;
    scoreMeaning: "PREVIEW_NOT_CYBERSCORE";
    customerSecurityStatus: "NOT_DETERMINED";
    providerLiveValidated: false;
    tenantCertifiedSecure: false;
    humanOperationalReviewDone: false;
  };
  sections: GoogleReportSection[];
  findings: GoogleReportFinding[];
  coverage: WorkspaceCoverageSummary[];
  actionPlan: ReturnType<typeof googleRemediationPlan>;
  evidenceManifest: ReturnType<typeof googleAssessmentManifest>;
  machineReadableJsonDigest: string;
  fullEvidenceDigest: string;
  recommendationsNotExecuted: true;
  sensitiveIdentitiesExported: false;
  sourceEmailsExported: false;
  sourceTokensExported: false;
  realTenantConsentProven: false;
  legalApprovalProven: false;
  externalProviderValidated: false;
  customerCertified: false;
  caveats: string[];
};
export type GoogleReportDiff = {
  schema: "cyberpilot.google.report.delta.v1";
  organizationId: string;
  baselineDigest: string;
  currentDigest: string;
  baselineTimestamp: string;
  currentTimestamp: string;
  sourceComparability: "SAME_SOURCE_CLASS" |
    "MIXED_SOURCE_CLASS_UNCOMPARABLE";
  findingsAdded: string[];
  findingsRemovedFromSnapshot: string[];
  findingsUnchanged: string[];
  coverageChanges: Array<{
    capability: GoogleCapability;
    previous: string;
    current: string;
    improvedLocally: boolean;
    deterioratedLocally: boolean;
    improvementProvesRemediation: false;
  }>;
  newlyUnknown: number;
  noLongerObservedCount: number;
  userPopulationComparable: boolean;
  resolvedRiskClaimed: false;
  cyberScoreDeltaClaimed: false;
  liveProviderVerified: false;
  digest: string;
};
export type GoogleHistoryPoint = {
  at: string;
  reportDigest: string;
  sourceDigest: string;
  users: number;
  potentialRisks: number;
  unknowns: number;
  coveragePercent: number;
  sourceClass: GoogleDirectoryObservation["source"];
  score: number | null;
};
export type GoogleHistorySeries = {
  schema: "cyberpilot.google.report.history.v1";
  organizationId: string;
  points: GoogleHistoryPoint[];
  gaps: Array<{ after: string; before: string; days: number }>;
  sourceClassesMixed: boolean;
  safeTrendLabel: "SNAPSHOT_ONLY_NO_REMEDIATION_CLAIM";
  trendIsFullTenantSecurity: false;
  reportCount: number;
  digest: string;
};
const caveats = [
  "Directory information can be incomplete due to permissions, edition, retention and pagination.",
  "The report summarizes technical development fixtures unless real provider consent is independently validated.",
  "An observed 2SV enrollment flag is not independent verification of every sign-in policy.",
  "The preview score is separate from canonical CyberScore and is null on partial/synthetic data.",
  "A risk disappearing from one report does not prove remediation or that the user is safe.",
  "No evidence of customer approval, compliance, certification or external provider authorization is collected.",
  "No account changes, administrator actions or provider permissions are altered by report generation.",
  "Only pseudonymous identity identifiers should be exported; original email addresses remain excluded.",
];
const order: WorkspaceReportSectionId[] = [
  "EXECUTIVE", "SCOPE", "IDENTITIES", "PRIVILEGES",
  "MULTIFACTOR", "DOMAINS", "AUDIT", "UNKNOWN",
  "RECOMMENDATIONS", "PROVENANCE", "LIMITATIONS",
];
function sha(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function same(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[0-9a-f]{64}$/.test(a) && /^[0-9a-f]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function fail(message: string): never {
  throw new Error("Invalid Google executive report: " + message);
}
export function summarizeGoogleReportCoverage(
  assessment: GoogleRiskAssessment,
): WorkspaceCoverageSummary[] {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Assessment failed verification.");
  return assessment.coverage.map(item => {
    const limitations: string[] = [];
    if (item.status === "PERMISSION_BLOCKED")
      limitations.push("Required API visibility is not granted.");
    if (item.status === "NOT_LICENSED")
      limitations.push("This signal may not be available in this edition.");
    if (item.status === "PARTIAL")
      limitations.push("The provider data was truncated or failed.");
    if (item.status === "COMPLETE_FIXTURE")
      limitations.push("Complete synthetic fixture does not attest a live provider.");
    if (item.status === "UNKNOWN")
      limitations.push("No reliable source observation was returned.");
    return {
      capability: item.capability, state: item.status,
      sourceCount: item.sourceCount,
      observedCount: item.usefulSignals,
      unknownCount: item.unknownSignals,
      completeness: item.status === "COMPLETE_FIXTURE" ||
        item.status === "OBSERVED_IN_ADAPTER" ?
          "VERIFIED_LOCAL_REFERENCE_ONLY" :
          item.status === "PERMISSION_BLOCKED" ||
          item.status === "NOT_LICENSED" ? "UNAVAILABLE" :
          item.status === "PARTIAL" ? "INCOMPLETE" : "UNKNOWN",
      confidence: item.scoreEligible ? "LOW" : "UNKNOWN",
      providerScopingLimitations: limitations,
    };
  });
}
function getEvidenceReferences(
  evidence: GoogleEvidenceRecord[], capability?: GoogleCapability,
) {
  return [...new Set(evidence.filter(e =>
    !capability || e.capability === capability)
    .map(e => e.sourceReference))].slice(0, 10);
}
function section(
  id: WorkspaceReportSectionId,
  title: string,
  description: string,
  findings: GoogleRiskAssessment["findings"],
  scope: string | null,
  sourceRefs: string[],
  actionLimit = 5,
): GoogleReportSection {
  const matching = scope === null ? findings :
    findings.filter(f => f.scope === scope);
  const potential = matching.filter(f =>
    f.status === "POTENTIAL_RISK");
  const unknown = matching.filter(f =>
    f.status === "INSUFFICIENT_EVIDENCE");
  const review = matching.filter(f => f.status === "NEEDS_REVIEW");
  const state: GoogleReportSection["state"] =
    unknown.length > 0 ? "INCOMPLETE" :
      potential.length > 0 ? "POTENTIAL_RISK" :
      review.length > 0 ? "NEEDS_REVIEW" : "INFORMATIONAL";
  return {
    id, title, state,
    headline: state === "INCOMPLETE" ?
      "Signals are insufficient to classify this section." :
      state === "POTENTIAL_RISK" ?
        "Potential security configuration issues need review." :
        state === "NEEDS_REVIEW" ?
          "Human interpretation is required." :
          "No potential issues identified in the observed subset.",
    description,
    observedItems: matching.length,
    potentialRisks: potential.length,
    unknownItems: unknown.length,
    evidenceReferences: sourceRefs,
    nextActions: matching.map(f => f.remediation)
      .filter((action, index, items) =>
        items.indexOf(action) === index).slice(0, actionLimit),
    customerApproved: false, completenessCertified: false,
  };
}
export function buildGoogleReportSections(
  assessment: GoogleRiskAssessment,
): GoogleReportSection[] {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Source assessment invalid.");
  const evidence = assessment.evidence;
  const findings = assessment.findings;
  const allRefs = getEvidenceReferences(evidence);
  const make = (id: WorkspaceReportSectionId,
    title: string, description: string, scope: string | null = null,
    reference: GoogleCapability | null = null) =>
    section(id, title, description, findings,
      scope, reference ? getEvidenceReferences(evidence, reference) :
        allRefs);
  const sections = [
    make("EXECUTIVE", "Executive summary",
      "Pseudonymous observed Directory evidence and provider coverage boundaries."),
    make("SCOPE", "Provider scope and source limitations",
      "Google Workspace is a separate provider. This report is not Microsoft Graph evidence."),
    make("IDENTITIES", "Directory identities",
      "Suspension, activity and lifecycle indicators require organization context.",
      "IDENTITY", "DIRECTORY_USERS"),
    make("PRIVILEGES", "Privileged accounts",
      "Directory administrator flags may not describe all delegated role privileges.",
      "IDENTITY", "DIRECTORY_USERS"),
    make("MULTIFACTOR", "2-step verification signals",
      "Enrollment and enforcement are separate observations; license and policy applicability may differ.",
      "IDENTITY", "USER_MFA_ATTRIBUTES"),
    make("DOMAINS", "Domain declarations",
      "Directory verification status does not assess SPF, DKIM, DMARC or external DNS exposure.",
      "DOMAIN", "DIRECTORY_DOMAINS"),
    make("AUDIT", "Login and admin events",
      "Reports API visibility is time-bounded, permission-limited and source-specific.",
      "TENANT", "REPORTS_LOGIN"),
    make("UNKNOWN", "Unavailable or partial evidence",
      "Errors, missing permissions and truncated data are never classified as healthy."),
    make("RECOMMENDATIONS", "Actions for administrator consideration",
      "All changes remain proposed until authorized independently."),
    make("PROVENANCE", "Evidence lineage",
      "Source and assessment SHA-256 references demonstrate only local content consistency."),
    make("LIMITATIONS", "Report limits",
      "No LIVE, compliance, certification, backup or customer approval can be inferred."),
  ];
  if (sections.map(s => s.id).join(",") !== order.join(","))
    fail("Report section order changed.");
  return sections;
}
export function buildGoogleExecutiveReport(
  assessment: GoogleRiskAssessment,
): GoogleReportExport {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Cannot prepare report from tampered assessment.");
  const coverage = summarizeGoogleReportCoverage(assessment);
  const sections = buildGoogleReportSections(assessment);
  const findings: GoogleReportFinding[] = assessment.findings.map(
    (f, index) => ({
      rank: index + 1, rule: f.ruleId,
      level: f.severity, status: f.status,
      title: f.title, whyItMatters: f.explanation,
      suggestedAction: f.remediation, verification: f.verification,
      sourceDigest: f.sourceDigest, evidenceRefs: f.evidenceIds,
      humanChangeApprovalNeeded: true,
      autoActionExecuted: false, thirdPartyValidated: false,
    }));
  const actionPlan = googleRemediationPlan(assessment);
  const evidenceManifest = googleAssessmentManifest(assessment);
  const summary = {
    usersObserved: assessment.counts.usersSeen,
    adminsObserved: assessment.counts.superadminsObserved,
    domainRecords: assessment.counts.domainsSeen,
    auditEvents: assessment.counts.auditEventsSeen,
    potentialRisks: assessment.counts.possibleRisks,
    unresolvedUnknowns: assessment.counts.unknownFindings,
    incompleteCapabilities: assessment.counts.incompleteCapabilities,
    previewScore: assessment.score.score,
    scoreMeaning: "PREVIEW_NOT_CYBERSCORE" as const,
    customerSecurityStatus: "NOT_DETERMINED" as const,
    providerLiveValidated: false as const,
    tenantCertifiedSecure: false as const,
    humanOperationalReviewDone: false as const,
  };
  const canonical = {
    schema: "cyberpilot.google.executive.report.v1" as const,
    organizationId: assessment.organizationId,
    referenceTimestamp: assessment.assessedAt,
    assessmentSourceDigest: assessment.sourceDigest,
    assessmentDigest: assessment.digest,
    reportScope: "GOOGLE_WORKSPACE_OFFLINE_DEVELOPMENT" as const,
    evidenceSourceClass: assessment.source,
    summary, sections, findings, coverage,
    actionPlan, evidenceManifest,
    recommendationsNotExecuted: true as const,
    sensitiveIdentitiesExported: false as const,
    sourceEmailsExported: false as const,
    sourceTokensExported: false as const,
    realTenantConsentProven: false as const,
    legalApprovalProven: false as const,
    externalProviderValidated: false as const,
    customerCertified: false as const,
  };
  return {
    ...canonical,
    machineReadableJsonDigest: sha(canonical),
    fullEvidenceDigest: assessment.digest,
    caveats,
  };
}
export function verifyGoogleExecutiveReport(report: GoogleReportExport) {
  const issues: string[] = [];
  const { machineReadableJsonDigest, fullEvidenceDigest, caveats: notes,
    ...canonical } = report;
  if (!same(machineReadableJsonDigest, sha(canonical)))
    issues.push("Report digest does not match fields.");
  if (!equalDigest(fullEvidenceDigest, report.assessmentDigest))
    issues.push("Report evidence is disconnected from assessment.");
  if (report.sections.length !== order.length ||
      report.sections.map(s => s.id).join(",") !== order.join(","))
    issues.push("Report section sequence incomplete.");
  if (report.coverage.length !== CAPABILITIES.length)
    issues.push("Report capability coverage incomplete.");
  if (report.summary.providerLiveValidated ||
      report.summary.tenantCertifiedSecure ||
      report.summary.humanOperationalReviewDone ||
      report.realTenantConsentProven ||
      report.legalApprovalProven ||
      report.externalProviderValidated || report.customerCertified ||
      report.sourceEmailsExported || report.sourceTokensExported ||
      report.sensitiveIdentitiesExported)
    issues.push("Report claims unverified LIVE, approval or secret export.");
  if (report.summary.scoreMeaning !== "PREVIEW_NOT_CYBERSCORE" ||
      report.summary.customerSecurityStatus !== "NOT_DETERMINED")
    issues.push("Preview score incorrectly promoted to security status.");
  if (report.actionPlan.some(action =>
    action.executedByConnector || action.approvedByCustomer))
    issues.push("A proposed action was marked as executed.");
  if (report.findings.some(f =>
    f.autoActionExecuted || f.thirdPartyValidated))
    issues.push("Finding claims remediation or third-party validation.");
  if (!Array.isArray(notes) || notes.length < 7)
    issues.push("Mandatory disclaimers were removed.");
  return { valid: issues.length === 0, issues };
}
export function exportGoogleReportJson(report: GoogleReportExport) {
  if (!verifyGoogleExecutiveReport(report).valid)
    fail("Cannot export altered report.");
  return JSON.stringify(report, null, 2) + "\n";
}
export function exportGoogleReportMarkdown(report: GoogleReportExport) {
  if (!verifyGoogleExecutiveReport(report).valid)
    fail("Cannot export altered report.");
  const sanitized = (s: string) => s.replaceAll("|", "/")
    .replace(/[<>]/g, "").replace(/[\r\n]/g, " ");
  const lines: string[] = [
    "# Google Workspace — offline evidence report",
    "",
    "Provider LIVE validated: NO; customer-approved: NO; certified: NO.",
    "Scope: synthetic or provider observation with independent limitations.",
    "Organization reference: " + report.organizationId,
    "Assessment digest: " + report.assessmentDigest,
    "",
    "## Executive summary",
    "",
    "| Indicator | Value |", "| --- | --- |",
  ];
  for (const [name, count] of [
    ["Observed users", report.summary.usersObserved],
    ["Observed superadministrators", report.summary.adminsObserved],
    ["Reported domains", report.summary.domainRecords],
    ["Possible risks", report.summary.potentialRisks],
    ["Unknown signals", report.summary.unresolvedUnknowns],
    ["Incomplete capabilities", report.summary.incompleteCapabilities],
  ] as const)
    lines.push("| " + sanitized(name) + " | " + count + " |");
  lines.push("", "## Coverage", "",
    "| Capability | Status | Observed signals | Unknown signals |",
    "| --- | --- | ---: | ---: |");
  for (const item of report.coverage)
    lines.push("| " + item.capability + " | " +
      sanitized(item.state) + " | " + item.observedCount +
      " | " + item.unknownCount + " |");
  lines.push("", "## Proposed risk actions", "");
  for (const item of report.findings) {
    lines.push("### " + item.rank + ". " + sanitized(item.title),
      "", "Status: " + item.status + ", severity: " + item.level,
      "", sanitized(item.whyItMatters), "",
      "Suggested: " + sanitized(item.suggestedAction), "",
      "Verify: " + sanitized(item.verification), "");
  }
  lines.push("## Limitations", "");
  for (const note of report.caveats)
    lines.push("- " + sanitized(note));
  return lines.join("\n") + "\n";
}
export function diffGoogleReports(
  previous: GoogleReportExport, current: GoogleReportExport,
): GoogleReportDiff {
  if (!verifyGoogleExecutiveReport(previous).valid ||
      !verifyGoogleExecutiveReport(current).valid)
    fail("Cannot compare invalid reports.");
  if (previous.organizationId !== current.organizationId)
    fail("Cross-tenant report comparison refused.");
  if (previous.referenceTimestamp > current.referenceTimestamp)
    fail("Report timestamps are not chronologically ordered.");
  const baseline = new Map(previous.findings.map(f =>
    [f.rule + ":" + f.evidenceRefs.join(","),
      f]));
  const latest = new Map(current.findings.map(f =>
    [f.rule + ":" + f.evidenceRefs.join(","),
      f]));
  const findingsAdded = [...latest.keys()]
    .filter(key => !baseline.has(key));
  const findingsRemovedFromSnapshot = [...baseline.keys()]
    .filter(key => !latest.has(key));
  const findingsUnchanged = [...latest.keys()]
    .filter(key => baseline.has(key));
  const previousCoverage = new Map(previous.coverage.map(c =>
    [c.capability, c]));
  const coverageChanges = current.coverage.map(item => {
    const old = previousCoverage.get(item.capability);
    if (!old) fail("Missing previous capability.");
    const good = (s: string) =>
      s === "COMPLETE_FIXTURE" || s === "OBSERVED_IN_ADAPTER";
    return {
      capability: item.capability,
      previous: old.state, current: item.state,
      improvedLocally: !good(old.state) && good(item.state),
      deterioratedLocally: good(old.state) && !good(item.state),
      improvementProvesRemediation: false as const,
    };
  });
  const previousUnknown = previous.findings.filter(f =>
    f.status === "INSUFFICIENT_EVIDENCE").length;
  const currentUnknown = current.findings.filter(f =>
    f.status === "INSUFFICIENT_EVIDENCE").length;
  const comparable = previous.reportScope === current.reportScope &&
    previous.evidenceSourceClass === current.evidenceSourceClass &&
    previous.summary.providerLiveValidated ===
      current.summary.providerLiveValidated;
  const canonical = {
    schema: "cyberpilot.google.report.delta.v1" as const,
    organizationId: current.organizationId,
    baselineDigest: previous.machineReadableJsonDigest,
    currentDigest: current.machineReadableJsonDigest,
    baselineTimestamp: previous.referenceTimestamp,
    currentTimestamp: current.referenceTimestamp,
    sourceComparability: comparable ?
      "SAME_SOURCE_CLASS" as const :
      "MIXED_SOURCE_CLASS_UNCOMPARABLE" as const,
    findingsAdded, findingsRemovedFromSnapshot,
    findingsUnchanged, coverageChanges,
    newlyUnknown: Math.max(0, currentUnknown - previousUnknown),
    noLongerObservedCount: findingsRemovedFromSnapshot.length,
    userPopulationComparable:
      previous.summary.usersObserved === current.summary.usersObserved,
    resolvedRiskClaimed: false as const,
    cyberScoreDeltaClaimed: false as const,
    liveProviderVerified: false as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyGoogleReportDiff(diff: GoogleReportDiff) {
  const { digest: fingerprint, ...canonical } = diff;
  const issues: string[] = [];
  if (!same(fingerprint, sha(canonical)))
    issues.push("Delta was altered.");
  if (diff.resolvedRiskClaimed || diff.cyberScoreDeltaClaimed ||
      diff.liveProviderVerified)
    issues.push("Delta implies unsupported verified remediation.");
  if (diff.coverageChanges.length !== CAPABILITIES.length)
    issues.push("Delta lacks capability comparisons.");
  if (diff.coverageChanges.some(change =>
    change.improvementProvesRemediation))
    issues.push("A coverage improvement is not a remediation proof.");
  return { valid: issues.length === 0, issues };
}
export function buildGoogleHistory(reports: GoogleReportExport[],
  maxGapDays = 30): GoogleHistorySeries {
  if (!Array.isArray(reports) || reports.length > 100)
    fail("History must be bounded.");
  if (!Number.isSafeInteger(maxGapDays) ||
      maxGapDays < 1 || maxGapDays > 365)
    fail("History gap threshold invalid.");
  if (!reports.every(r => verifyGoogleExecutiveReport(r).valid))
    fail("History contains a tampered report.");
  if (reports.length === 0)
    fail("History requires at least one evidence report.");
  const organizationId = reports[0]!.organizationId;
  if (reports.some(r => r.organizationId !== organizationId))
    fail("History cannot combine organizations.");
  const sorted = [...reports].sort((a, b) =>
    a.referenceTimestamp.localeCompare(b.referenceTimestamp) ||
    a.machineReadableJsonDigest.localeCompare(b.machineReadableJsonDigest));
  if (new Set(sorted.map(r => r.machineReadableJsonDigest)).size !==
      sorted.length)
    fail("History repeats the same report snapshot.");
  const points: GoogleHistoryPoint[] = sorted.map(r => ({
    at: r.referenceTimestamp,
    reportDigest: r.machineReadableJsonDigest,
    sourceDigest: r.assessmentSourceDigest,
    users: r.summary.usersObserved,
    potentialRisks: r.summary.potentialRisks,
    unknowns: r.summary.unresolvedUnknowns,
    coveragePercent: Math.round(100 * r.coverage.filter(c =>
      c.completeness === "VERIFIED_LOCAL_REFERENCE_ONLY").length /
      CAPABILITIES.length),
    sourceClass: r.evidenceSourceClass,
    score: r.summary.previewScore,
  }));
  const gaps: GoogleHistorySeries["gaps"] = [];
  for (let i = 1; i < points.length; i++) {
    const before = points[i - 1]!, after = points[i]!;
    const days = Math.floor((Date.parse(after.at) -
      Date.parse(before.at)) / 86400000);
    if (days > maxGapDays)
      gaps.push({ after: before.at, before: after.at, days });
  }
  const canonical = {
    schema: "cyberpilot.google.report.history.v1" as const,
    organizationId, points, gaps,
    sourceClassesMixed: new Set(points.map(p => p.sourceClass)).size > 1,
    safeTrendLabel: "SNAPSHOT_ONLY_NO_REMEDIATION_CLAIM" as const,
    trendIsFullTenantSecurity: false as const,
    reportCount: points.length,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyGoogleHistory(history: GoogleHistorySeries) {
  const { digest: fingerprint, ...canonical } = history;
  const issues: string[] = [];
  if (!same(fingerprint, sha(canonical)))
    issues.push("History digest mismatch.");
  if (history.trendIsFullTenantSecurity ||
      history.safeTrendLabel !== "SNAPSHOT_ONLY_NO_REMEDIATION_CLAIM")
    issues.push("History overstates available security evidence.");
  if (history.reportCount !== history.points.length ||
      history.points.length > 100)
    issues.push("History size is inconsistent.");
  if (new Set(history.points.map(p => p.reportDigest)).size !==
      history.points.length)
    issues.push("History contains duplicate snapshots.");
  return { valid: issues.length === 0, issues };
}
export function inspectGoogleOfflineFixture(
  observation: GoogleDirectoryObservation,
  now = new Date(),
) {
  const assessment = assessGoogleWorkspace(observation, {}, now);
  const report = buildGoogleExecutiveReport(assessment);
  const valid = verifyGoogleExecutiveReport(report);
  if (!valid.valid)
    fail("New offline report failed integrity verification.");
  return { assessment, report, validation: valid,
    markdown: exportGoogleReportMarkdown(report),
    actionPlan: googleRemediationPlan(assessment),
    sourceClass: observation.source,
    customerLiveValidated: false as const,
    accountWrites: 0 as const,
  };
}
