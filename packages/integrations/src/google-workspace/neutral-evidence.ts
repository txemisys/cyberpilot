import { canonicalGoogleHash } from "./canonical-json";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  CAPABILITIES, type GoogleCapability,
  type GoogleEvidenceRecord,
} from "./directory-contract";
import {
  verifyGoogleRiskAssessment,
  type GoogleRiskAssessment, type GoogleFinding,
} from "./risk-assessment";

/**
 * Neutral provider projection. It is deliberately independent of a
 * canonical CyberScore version, current M365 scoring and any Google LIVE
 * OAuth connection. Every exported row retains source capability and
 * evidence incompleteness, so partial coverage never becomes HEALTHY.
 */
export type NeutralGoogleState =
  "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type NeutralGoogleDomain =
  "IDENTITY" | "ACCESS" | "MONITORING" |
  "INVENTORY" | "COVERAGE";
export type NeutralGoogleControl = {
  schema: "cyberpilot.neutral.provider.control.v1";
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  source: "GOOGLE_DIRECTORY" | "GOOGLE_REPORTS" |
    "SYNTHETIC_FIXTURE";
  domain: NeutralGoogleDomain;
  controlId: string;
  state: NeutralGoogleState;
  scope: string;
  subjectHash: string;
  observedAt: string | null;
  checkedAt: string;
  confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  version: 1;
  providerCapability: GoogleCapability;
  sourceDigest: string;
  sourceReference: string;
  sourceCoverage: "COMPLETE_LOCAL_FIXTURE" |
    "PARTIAL" | "UNKNOWN" | "DENIED";
  limitations: string[];
  details: Record<string, string | number | boolean | null>;
  discoveryMechanism: "PASSIVE_DECLARATION_OR_READ_ONLY";
  externalLiveProviderVerified: false;
  independentSecurityCertified: false;
  usedForCyberScore: false;
};
export type NeutralGoogleFinding = {
  schema: "cyberpilot.neutral.provider.finding.v1";
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  findingKey: string;
  ruleId: string;
  state: "POTENTIAL" | "REVIEW" | "UNKNOWN";
  severity: "CRITICAL" | "HIGH" | "MEDIUM" |
    "LOW" | "INFO" | "UNKNOWN";
  title: string;
  summary: string;
  remediation: string;
  verification: string;
  evidenceControlIds: string[];
  subjectHash: string;
  sourceDigest: string;
  firstSeenAt: string;
  lastSeenAt: string;
  resolved: false;
  assetExploitableVerified: false;
  GoogleAccountMutated: false;
  customerApproved: false;
};
export type NeutralGoogleCoverage = {
  schema: "cyberpilot.neutral.provider.coverage.v1";
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  assessedAt: string;
  sourceDigest: string;
  capabilities: Array<{
    capability: GoogleCapability;
    controlRows: number;
    observed: number;
    unknown: number;
    errored: number;
    status: "COMPLETE_LOCAL_ONLY" | "PARTIAL" |
      "DENIED" | "UNKNOWN";
    canClaimHealthy: false;
  }>;
  fullyCoveredCapabilities: number;
  totalCapabilities: number;
  sourceCoveragePercent: number;
  fullTenantScopeVerified: false;
  externalProviderVerified: false;
  canonicalCyberScoreChanged: false;
  comparableToM365ByNormalizedControl: true;
  providerSecurityEquivalenceProven: false;
};
export type NeutralGoogleBundle = {
  schema: "cyberpilot.neutral.google.bundle.v1";
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  assessedAt: string;
  sourceDigest: string;
  assessmentDigest: string;
  sourceClass: "GOOGLE_DIRECTORY" | "SYNTHETIC_FIXTURE";
  controls: NeutralGoogleControl[];
  findings: NeutralGoogleFinding[];
  coverage: NeutralGoogleCoverage;
  summary: {
    controls: number;
    findings: number;
    possibleRisks: number;
    review: number;
    unknown: number;
    errors: number;
    incompleteCapabilities: number;
    sourceIsSynthetic: boolean;
    canonicalScore: null;
    canonicalScoreUpdated: false;
  };
  provenance: {
    schemaVersion: 1;
    sourceDigest: string;
    assessedAt: string;
    provider: "GOOGLE_WORKSPACE";
    sourceClass: "GOOGLE_DIRECTORY" | "SYNTHETIC_FIXTURE";
    authScope: "OFFLINE_OR_CONSENT_REQUIRED";
    sourceSignatureVerified: false;
    licensingVerified: false;
  };
  exportRestrictions: {
    rawEmailIncluded: false;
    rawIpIncluded: false;
    oauthCredentialIncluded: false;
    directRemediationPerformed: false;
    customerAcceptanceVerified: false;
    thirdPartyLiveValidationVerified: false;
    crossTenantMergePermitted: false;
  };
  limitations: string[];
  digest: string;
};
export type NeutralGoogleComparison = {
  schema: "cyberpilot.neutral.google.comparison.v1";
  organizationId: string;
  baselineDigest: string;
  currentDigest: string;
  addedFindings: string[];
  absentFromNewSnapshot: string[];
  unchangedFindings: string[];
  changedControls: Array<{
    controlKey: string;
    before: NeutralGoogleState | null;
    after: NeutralGoogleState | null;
    changed: boolean;
    verifiedRemediation: false;
  }>;
  newlyUncoveredCapabilities: GoogleCapability[];
  newlyCoveredLocally: GoogleCapability[];
  comparableSourceClass: boolean;
  sourceReverification: false;
  officialRemediationClaimed: false;
  canonicalCyberScoreRecomputed: false;
  digest: string;
};
const limitations = [
  "Google Workspace and Microsoft 365 expose different provider capabilities.",
  "A normalized OBSERVED flag does not by itself prove a healthy control.",
  "A local fixture is not authenticated Google Directory or Reports evidence.",
  "UNKNOWN, ERROR and partial provider results remain explicit.",
  "No LIVE Google API, OAuth consent or provider availability is certified.",
  "No neutral projection updates the canonical historical CyberScore.",
  "Source digests verify local consistency, not third-party signatures.",
  "Potential findings are advisory and require policy context before action.",
];
const domains: Record<GoogleCapability, NeutralGoogleDomain> = {
  DIRECTORY_USERS: "IDENTITY",
  USER_MFA_ATTRIBUTES: "ACCESS",
  DIRECTORY_DOMAINS: "INVENTORY",
  DIRECTORY_ORGANIZATION_UNITS: "INVENTORY",
  REPORTS_LOGIN: "MONITORING",
  REPORTS_ADMIN: "MONITORING",
};
function hash(value: unknown) {
  return canonicalGoogleHash(value);
}
function equal(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function fail(message: string): never {
  throw new Error("Neutral Google evidence rejected: " + message);
}
function capabilityState(
  assessment: GoogleRiskAssessment, capability: GoogleCapability,
): NeutralGoogleControl["sourceCoverage"] {
  const row = assessment.coverage.find(x => x.capability === capability);
  if (!row) fail("Missing provider capability.");
  if (row.status === "PERMISSION_BLOCKED") return "DENIED";
  if (row.status === "PARTIAL") return "PARTIAL";
  if (row.status === "COMPLETE_FIXTURE" ||
      row.status === "OBSERVED_IN_ADAPTER") return "COMPLETE_LOCAL_FIXTURE";
  return "UNKNOWN";
}
function normalizeSource(source: GoogleEvidenceRecord["sourceType"]) {
  return source === "GOOGLE_DIRECTORY" ||
    source === "GOOGLE_REPORTS" ? source : "SYNTHETIC_FIXTURE";
}
function safeControlDetail(details: GoogleEvidenceRecord["details"]) {
  const out: NeutralGoogleControl["details"] = {};
  for (const [key, value] of Object.entries(details)) {
    if (/email|token|password|secret|phone|ipaddress|credential/i.test(key))
      continue;
    if (Object.keys(out).length >= 32) break;
    if (typeof value === "string" &&
        (value.length > 200 || /[\u0000-\u001f\u007f]/.test(value)))
      continue;
    out[key] = value;
  }
  return out;
}
function controlName(record: GoogleEvidenceRecord) {
  return [
    "GOOGLE_WORKSPACE", record.capability,
    record.controlId, record.subjectHash,
  ].join(":");
}
export function translateGoogleEvidence(
  assessment: GoogleRiskAssessment,
): NeutralGoogleControl[] {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Risk assessment source digest invalid.");
  if (assessment.evidence.length > 20000)
    fail("Evidence projection exceeds safe capacity.");
  const seen = new Set<string>();
  return assessment.evidence.map(record => {
    if (record.organizationId !== assessment.organizationId ||
        record.sourceReference !== assessment.sourceDigest ||
        record.externalLiveVerified ||
        record.customerOperationalApproval)
      fail("Source evidence is outside verified offline scope.");
    const name = controlName(record);
    if (seen.has(name))
      fail("Duplicate evidence identity would overwrite a control.");
    seen.add(name);
    const coverage = capabilityState(assessment,
      record.capability);
    const state = coverage !== "COMPLETE_LOCAL_FIXTURE" &&
      record.state === "OBSERVED" ? "UNKNOWN" : record.state;
    const context = [
      "Provider capability: " + record.capability,
      "Source class: " + record.sourceType,
      "No independent live provider or customer authorization verified.",
    ];
    if (state !== "OBSERVED")
      context.push("Coverage is unavailable, partial or unobserved.");
    if (record.confidence === "UNKNOWN")
      context.push("No confidence claim is warranted.");
    return {
      schema: "cyberpilot.neutral.provider.control.v1",
      organizationId: assessment.organizationId,
      provider: "GOOGLE_WORKSPACE",
      source: normalizeSource(record.sourceType),
      domain: domains[record.capability],
      controlId: record.controlId,
      state, scope: record.scope,
      subjectHash: record.subjectHash,
      observedAt: state === "OBSERVED" ?
        record.observedAt : null,
      checkedAt: record.checkedAt,
      confidence: state === "OBSERVED" ?
        record.confidence : "UNKNOWN",
      version: 1,
      providerCapability: record.capability,
      sourceDigest: assessment.sourceDigest,
      sourceReference: record.sourceReference,
      sourceCoverage: coverage,
      limitations: context,
      details: safeControlDetail(record.details),
      discoveryMechanism: "PASSIVE_DECLARATION_OR_READ_ONLY",
      externalLiveProviderVerified: false,
      independentSecurityCertified: false,
      usedForCyberScore: false,
    };
  });
}
function neutralFinding(
  assessment: GoogleRiskAssessment,
  item: GoogleFinding,
): NeutralGoogleFinding {
  if (item.organizationId !== assessment.organizationId ||
      item.sourceDigest !== assessment.sourceDigest ||
      item.automaticallyRemediated ||
      item.actualProviderValidated)
    fail("Google finding outside verified source scope.");
  return {
    schema: "cyberpilot.neutral.provider.finding.v1",
    organizationId: assessment.organizationId,
    provider: "GOOGLE_WORKSPACE",
    findingKey: hash({
      provider: "GOOGLE_WORKSPACE",
      organizationId: assessment.organizationId,
      ruleId: item.ruleId, subjectHash: item.subjectHash,
    }),
    ruleId: item.ruleId,
    state: item.status === "POTENTIAL_RISK" ?
      "POTENTIAL" : item.status === "NEEDS_REVIEW" ?
        "REVIEW" : "UNKNOWN",
    severity: item.severity,
    title: item.title, summary: item.explanation,
    remediation: item.remediation,
    verification: item.verification,
    evidenceControlIds: [...item.evidenceIds],
    subjectHash: item.subjectHash,
    sourceDigest: item.sourceDigest,
    firstSeenAt: assessment.assessedAt,
    lastSeenAt: assessment.assessedAt,
    resolved: false,
    assetExploitableVerified: false,
    GoogleAccountMutated: false,
    customerApproved: false,
  };
}
export function translateGoogleFindings(
  assessment: GoogleRiskAssessment,
): NeutralGoogleFinding[] {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Cannot translate altered Google assessment.");
  const output = assessment.findings.map(item =>
    neutralFinding(assessment, item));
  if (output.length > 10000)
    fail("Potential finding set exceeds safe maximum.");
  const keys = output.map(item => item.findingKey);
  if (new Set(keys).size !== keys.length)
    fail("Google finding keys are not unique.");
  return output;
}
export function buildNeutralGoogleCoverage(
  assessment: GoogleRiskAssessment,
  controls: NeutralGoogleControl[],
): NeutralGoogleCoverage {
  const capabilities = CAPABILITIES.map(capability => {
    const subset = controls.filter(row =>
      row.providerCapability === capability);
    const status = capabilityState(assessment, capability);
    return {
      capability,
      controlRows: subset.length,
      observed: subset.filter(x => x.state === "OBSERVED").length,
      unknown: subset.filter(x => x.state === "UNKNOWN").length,
      errored: subset.filter(x => x.state === "ERROR").length,
      status: status === "COMPLETE_LOCAL_FIXTURE" ?
        "COMPLETE_LOCAL_ONLY" as const :
        status === "PARTIAL" ? "PARTIAL" as const :
        status === "DENIED" ? "DENIED" as const : "UNKNOWN" as const,
      canClaimHealthy: false as const,
    };
  });
  const complete = capabilities.filter(c =>
    c.status === "COMPLETE_LOCAL_ONLY").length;
  return {
    schema: "cyberpilot.neutral.provider.coverage.v1",
    organizationId: assessment.organizationId,
    provider: "GOOGLE_WORKSPACE",
    assessedAt: assessment.assessedAt,
    sourceDigest: assessment.sourceDigest,
    capabilities,
    fullyCoveredCapabilities: complete,
    totalCapabilities: capabilities.length,
    sourceCoveragePercent:
      Math.round(100 * complete / capabilities.length),
    fullTenantScopeVerified: false,
    externalProviderVerified: false,
    canonicalCyberScoreChanged: false,
    comparableToM365ByNormalizedControl: true,
    providerSecurityEquivalenceProven: false,
  };
}
export function buildNeutralGoogleBundle(
  assessment: GoogleRiskAssessment,
): NeutralGoogleBundle {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    fail("Assessment has invalid digest or claims.");
  const controls = translateGoogleEvidence(assessment);
  const findings = translateGoogleFindings(assessment);
  const coverage = buildNeutralGoogleCoverage(assessment,
    controls);
  const summary = {
    controls: controls.length, findings: findings.length,
    possibleRisks: findings.filter(f =>
      f.state === "POTENTIAL").length,
    review: findings.filter(f => f.state === "REVIEW").length,
    unknown: findings.filter(f => f.state === "UNKNOWN").length,
    errors: controls.filter(c => c.state === "ERROR").length,
    incompleteCapabilities: coverage.capabilities.filter(c =>
      c.status !== "COMPLETE_LOCAL_ONLY").length,
    sourceIsSynthetic: assessment.source === "SYNTHETIC_FIXTURE",
    canonicalScore: null,
    canonicalScoreUpdated: false as const,
  };
  const canonical = {
    schema: "cyberpilot.neutral.google.bundle.v1" as const,
    organizationId: assessment.organizationId,
    provider: "GOOGLE_WORKSPACE" as const,
    assessedAt: assessment.assessedAt,
    sourceDigest: assessment.sourceDigest,
    assessmentDigest: assessment.digest,
    sourceClass: assessment.source,
    controls, findings, coverage, summary,
    provenance: {
      schemaVersion: 1 as const,
      sourceDigest: assessment.sourceDigest,
      assessedAt: assessment.assessedAt,
      provider: "GOOGLE_WORKSPACE" as const,
      sourceClass: assessment.source,
      authScope: "OFFLINE_OR_CONSENT_REQUIRED" as const,
      sourceSignatureVerified: false as const,
      licensingVerified: false as const,
    },
    exportRestrictions: {
      rawEmailIncluded: false as const,
      rawIpIncluded: false as const,
      oauthCredentialIncluded: false as const,
      directRemediationPerformed: false as const,
      customerAcceptanceVerified: false as const,
      thirdPartyLiveValidationVerified: false as const,
      crossTenantMergePermitted: false as const,
    },
    limitations: [...limitations],
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyNeutralGoogleBundle(bundle: NeutralGoogleBundle) {
  const { digest, ...canonical } = bundle;
  const issues: string[] = [];
  if (!equal(digest, hash(canonical)))
    issues.push("Neutral Google bundle contents altered.");
  if (bundle.schema !== "cyberpilot.neutral.google.bundle.v1" ||
      bundle.provider !== "GOOGLE_WORKSPACE" ||
      bundle.coverage.organizationId !== bundle.organizationId)
    issues.push("Neutral source identity inconsistent.");
  if (bundle.provenance.sourceDigest !== bundle.sourceDigest ||
      bundle.provenance.sourceClass !== bundle.sourceClass)
    issues.push("Neutral source lineage inconsistent.");
  if (bundle.exportRestrictions.rawEmailIncluded ||
      bundle.exportRestrictions.rawIpIncluded ||
      bundle.exportRestrictions.oauthCredentialIncluded ||
      bundle.exportRestrictions.directRemediationPerformed ||
      bundle.exportRestrictions.customerAcceptanceVerified ||
      bundle.exportRestrictions.thirdPartyLiveValidationVerified ||
      bundle.exportRestrictions.crossTenantMergePermitted)
    issues.push("Neutral bundle contains unsupported PII or assurance claim.");
  if (bundle.summary.canonicalScore !== null ||
      bundle.summary.canonicalScoreUpdated ||
      bundle.coverage.canonicalCyberScoreChanged ||
      bundle.coverage.externalProviderVerified ||
      bundle.coverage.fullTenantScopeVerified)
    issues.push("Neutral bundle cannot modify or certify CyberScore.");
  if (bundle.controls.some(c => c.organizationId !==
      bundle.organizationId || c.sourceDigest !== bundle.sourceDigest ||
      c.usedForCyberScore || c.externalLiveProviderVerified))
    issues.push("Neutral control crossed scope or made unsupported claims.");
  if (bundle.findings.some(f => f.organizationId !==
      bundle.organizationId || f.sourceDigest !== bundle.sourceDigest ||
      f.resolved || f.GoogleAccountMutated || f.customerApproved))
    issues.push("Neutral finding claims unsupported action or source.");
  if (bundle.coverage.capabilities.length !== CAPABILITIES.length)
    issues.push("Neutral capability catalog is incomplete.");
  if (bundle.summary.controls !== bundle.controls.length ||
      bundle.summary.findings !== bundle.findings.length)
    issues.push("Neutral bundle count mismatch.");
  if (!Array.isArray(bundle.limitations) ||
      bundle.limitations.length < limitations.length)
    issues.push("Neutral limitations omitted.");
  return { valid: issues.length === 0, issues };
}
export function compareNeutralGoogleBundles(
  previous: NeutralGoogleBundle,
  next: NeutralGoogleBundle,
): NeutralGoogleComparison {
  if (!verifyNeutralGoogleBundle(previous).valid ||
      !verifyNeutralGoogleBundle(next).valid)
    fail("Cannot compare invalid neutral evidence bundles.");
  if (previous.organizationId !== next.organizationId)
    fail("Cross-organization neutral comparisons are prohibited.");
  if (previous.assessedAt > next.assessedAt)
    fail("Neutral snapshots are out of chronological order.");
  const beforeKeys = new Set(previous.findings.map(x =>
    x.findingKey));
  const afterKeys = new Set(next.findings.map(x =>
    x.findingKey));
  const oldControls = new Map(previous.controls.map(c =>
    [controlNameForComparison(c), c.state]));
  const newControls = new Map(next.controls.map(c =>
    [controlNameForComparison(c), c.state]));
  const allKeys = [...new Set([
    ...oldControls.keys(), ...newControls.keys(),
  ])].sort();
  const changedControls = allKeys.map(controlKey => {
    const before = oldControls.get(controlKey) ?? null;
    const after = newControls.get(controlKey) ?? null;
    return {
      controlKey, before, after,
      changed: before !== after,
      verifiedRemediation: false as const,
    };
  }).filter(row => row.changed);
  const status = (b: NeutralGoogleBundle, c: GoogleCapability) =>
    b.coverage.capabilities.find(row =>
      row.capability === c)?.status === "COMPLETE_LOCAL_ONLY";
  const canonical = {
    schema: "cyberpilot.neutral.google.comparison.v1" as const,
    organizationId: next.organizationId,
    baselineDigest: previous.digest,
    currentDigest: next.digest,
    addedFindings: [...afterKeys].filter(x =>
      !beforeKeys.has(x)).sort(),
    absentFromNewSnapshot: [...beforeKeys].filter(x =>
      !afterKeys.has(x)).sort(),
    unchangedFindings: [...afterKeys].filter(x =>
      beforeKeys.has(x)).sort(),
    changedControls,
    newlyUncoveredCapabilities: CAPABILITIES.filter(c =>
      status(previous, c) && !status(next, c)),
    newlyCoveredLocally: CAPABILITIES.filter(c =>
      !status(previous, c) && status(next, c)),
    comparableSourceClass:
      previous.sourceClass === next.sourceClass,
    sourceReverification: false as const,
    officialRemediationClaimed: false as const,
    canonicalCyberScoreRecomputed: false as const,
  };
  return { ...canonical, digest: hash(canonical) };
}
function controlNameForComparison(control: NeutralGoogleControl) {
  return [
    control.provider, control.providerCapability,
    control.controlId, control.subjectHash,
  ].join(":");
}
export function verifyNeutralGoogleComparison(
  comparison: NeutralGoogleComparison,
) {
  const { digest, ...canonical } = comparison;
  const issues: string[] = [];
  if (!equal(digest, hash(canonical)))
    issues.push("Neutral comparison integrity failed.");
  if (comparison.officialRemediationClaimed ||
      comparison.canonicalCyberScoreRecomputed ||
      comparison.sourceReverification)
    issues.push("Neutral comparison claims unverified remediation.");
  if (comparison.changedControls.some(x =>
    x.verifiedRemediation))
    issues.push("Comparison claims a completed remediation.");
  return { valid: issues.length === 0, issues };
}
export function neutralGoogleCsv(
  bundle: NeutralGoogleBundle,
) {
  if (!verifyNeutralGoogleBundle(bundle).valid)
    fail("Cannot export altered neutral Google evidence.");
  const safe = (value: string) => {
    if (/[\u0000-\u001f\u007f]/.test(value))
      fail("Unsafe control text.");
    const sanitized = /^[=+@\-]/.test(value) ?
      "'" + value : value;
    return '"' + sanitized.replaceAll('"', '""') + '"';
  };
  const rows = [
    ["provider", "domain", "controlId", "state",
      "capability", "scope", "subjectHash", "sourceDigest",
      "coverage", "checkedAt"],
  ];
  for (const c of bundle.controls) rows.push([
    c.provider, c.domain, c.controlId,
    c.state, c.providerCapability, c.scope,
    c.subjectHash, c.sourceDigest,
    c.sourceCoverage, c.checkedAt,
  ]);
  return rows.map(row => row.map(safe).join(",")).join("\r\n") +
    "\r\n";
}
export function neutralGoogleJson(bundle: NeutralGoogleBundle) {
  if (!verifyNeutralGoogleBundle(bundle).valid)
    fail("Cannot export altered neutral Google evidence.");
  return JSON.stringify(bundle, null, 2) + "\n";
}
