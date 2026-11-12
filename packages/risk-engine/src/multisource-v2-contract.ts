/**
 * CyberPilot multi-source v2 is an opt-in assessment protocol.
 * It never changes a stored v1 CyberScore or treats unobserved scope
 * as healthy. This module is deterministic, tenant-bound and offline.
 */
export type V2Source =
  "MICROSOFT_365" | "GOOGLE_WORKSPACE" | "LAB" |
  "EXPOSURE" | "BASELINE" | "ASSETS";
export type V2Domain =
  "IDENTITY" | "EMAIL" | "WEB" | "ENDPOINT" |
  "BACKUP" | "GOVERNANCE" | "EXPOSURE";
export type V2State =
  "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type V2Confidence =
  "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type V2Verification =
  "TECHNICALLY_VERIFIED" | "OPERATOR_DECLARED" |
  "SYNTHETIC_FIXTURE" | "NOT_VERIFIED";
export type V2ScopeKind =
  "ORGANIZATION" | "DOMAIN" | "USER" |
  "DEVICE" | "SERVICE" | "WORKLOAD";
export type V2Severity =
  "CRITICAL" | "HIGH" | "MEDIUM" |
  "LOW" | "INFO" | "UNKNOWN";
export type V2Evidence = {
  schema: "cyberpilot.multisource.evidence.v2";
  organizationId: string;
  evidenceId: string;
  source: V2Source;
  domain: V2Domain;
  controlId: string;
  scope: string;
  scopeKind: V2ScopeKind;
  subjectHash: string;
  state: V2State;
  confidence: V2Confidence;
  verification: V2Verification;
  observedAt: string | null;
  checkedAt: string;
  validUntil: string | null;
  sourceDigest: string;
  sourceReference: string;
  authority: string;
  sourceCoverage: "COMPLETE" | "PARTIAL" |
    "DENIED" | "UNKNOWN";
  details: Record<string, string | number | boolean | null>;
  rawPersonalDataStored: false;
  providerAccountModified: false;
  customerApprovalInferred: false;
};
export type V2ControlSpec = {
  schema: "cyberpilot.multisource.control.v2";
  id: string;
  domain: V2Domain;
  scope: V2ScopeKind;
  weight: number;
  criticality: "CRITICAL" | "HIGH" | "NORMAL";
  acceptedSources: V2Source[];
  requiredVerification: "TECHNICAL" | "DECLARATION_ACCEPTABLE";
  maxAgeDays: number;
  applicability: "REQUIRED" | "OPTIONAL";
  title: string;
  description: string;
};
export type V2Finding = {
  schema: "cyberpilot.multisource.finding.v2";
  organizationId: string;
  findingId: string;
  ruleId: string;
  domain: V2Domain;
  controlId: string;
  scope: string;
  subjectHash: string;
  source: V2Source;
  severity: V2Severity;
  state: "POTENTIAL_RISK" | "REQUIRES_REVIEW" |
    "UNKNOWN";
  title: string;
  explanation: string;
  remediation: string;
  evidenceIds: string[];
  observedAt: string;
  confidence: V2Confidence;
  autoRemediated: false;
  customerAccepted: false;
  resolved: false;
};
export type V2Scope = {
  organizationId: string;
  source: V2Source;
  domain: V2Domain;
  scopeKind: V2ScopeKind;
  scope: string;
  expectedSubjects: number | null;
  observedSubjects: number | null;
  totalPages: number | null;
  pagesObserved: number | null;
  status: "COMPLETE" | "PARTIAL" |
    "PERMISSION_DENIED" | "ERROR" | "UNASSESSED";
  checkedAt: string;
  validUntil: string | null;
  sourceDigest: string;
  customerTenantAuthenticated: boolean;
  scopeAuthenticityVerified: boolean;
  errors: string[];
};
export type V2Manifest = {
  schema: "cyberpilot.multisource.manifest.v2";
  organizationId: string;
  snapshotId: string;
  evaluatedAt: string;
  modelId: "cyberpilot.multisource.v2";
  modelRevision: 1;
  expectedDomains: V2Domain[];
  expectedControls: V2ControlSpec[];
  evidence: V2Evidence[];
  findings: V2Finding[];
  scopes: V2Scope[];
  sourceDigests: string[];
  historicalCyberScoreTouched: false;
  externalLiveConsentVerified: false;
  customerApprovalAttested: false;
};
export type V2Status =
  "OBSERVED" | "DECLARED" | "UNKNOWN" |
  "ERROR" | "STALE" | "CONFLICT";
export type V2CoverageRow = {
  controlId: string;
  domain: V2Domain;
  scopeKind: V2ScopeKind;
  weight: number;
  applicability: V2ControlSpec["applicability"];
  requirement: V2ControlSpec["requiredVerification"];
  status: V2Status;
  sourceIds: V2Source[];
  evidenceIds: string[];
  verifiedEvidenceIds: string[];
  missingSources: V2Source[];
  checkedAt: string | null;
  observedAt: string | null;
  scope: string;
  scopeComplete: boolean;
  evidenceFresh: boolean;
  authenticatedLiveEvidence: boolean;
  verifiedForScoring: boolean;
  findings: number;
  knownRisks: number;
  uncertainty: string[];
  issues: string[];
};
export type V2DomainCoverage = {
  domain: V2Domain;
  expectedControls: number;
  observedControls: number;
  declaredControls: number;
  unknownControls: number;
  errorControls: number;
  staleControls: number;
  conflictControls: number;
  weightTotal: number;
  verifiedWeight: number;
  coveragePercent: number;
  verified: boolean;
  healthyAllowed: boolean;
  sources: V2Source[];
  missingControls: string[];
  limitations: string[];
};
export type V2Coverage = {
  schema: "cyberpilot.multisource.coverage.v2";
  organizationId: string;
  evaluatedAt: string;
  modelId: "cyberpilot.multisource.v2";
  controls: V2CoverageRow[];
  domains: V2DomainCoverage[];
  requiredWeight: number;
  verifiedWeight: number;
  partialWeight: number;
  unknownWeight: number;
  coveragePercent: number;
  totalControls: number;
  verifiedControls: number;
  missingControls: number;
  conflicts: number;
  stale: number;
  errors: number;
  sources: V2Source[];
  liveProviderAuthenticated: boolean;
  syntheticDataPresent: boolean;
  fullTenantCoverageProven: boolean;
  sourceEquivalenceProven: false;
  canonicalV1ScoreChanged: false;
  healthClaimPermitted: boolean;
  warnings: string[];
};
export type V2RiskContribution = {
  key: string;
  ruleId: string;
  severity: V2Severity;
  domain: V2Domain;
  source: V2Source;
  subjectHash: string;
  evidenceIds: string[];
  assessedControlIds: string[];
  riskWeight: number;
  confidenceMultiplier: number;
  scopeMultiplier: number;
  rawPoints: number;
  appliedPoints: number;
  limitedByDomain: boolean;
  confidence: V2Confidence;
  actionable: boolean;
  unverifiable: boolean;
  rationale: string;
};
export type V2Score = {
  schema: "cyberpilot.multisource.score.v2";
  organizationId: string;
  modelId: "cyberpilot.multisource.v2";
  modelRevision: 1;
  evaluatedAt: string;
  score: number | null;
  scoreRange: {
    min: number;
    max: number;
  };
  riskPoints: number;
  maximumRiskPoints: number;
  coveragePercent: number;
  adjustedRisk: number;
  status: "ASSESSED_WITH_LIMITATIONS" |
    "INSUFFICIENT_COVERAGE" | "UNASSESSABLE" |
    "INVALID_EVIDENCE";
  label: "NOT_CERTIFIED" | "UNDETERMINED";
  confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  contributions: V2RiskContribution[];
  unsupportedFindings: string[];
  unknownControls: string[];
  excludedFindings: string[];
  topActions: Array<{
    findingId: string;
    title: string;
    severity: V2Severity;
    rationale: string;
    recommendation: string;
    source: V2Source;
    evidenceIds: string[];
    verifiedAction: false;
  }>;
  legacyScore: null;
  legacyCyberScoreRecomputed: false;
  eligibleForProductHealthBadge: false;
  modelMigrationCompleted: false;
  noVerifiedCustomerCompliance: true;
  limitations: string[];
};
export type V2Validation = {
  valid: boolean;
  organizationId: string | null;
  checked: number;
  accepted: number;
  rejected: number;
  duplicates: string[];
  crossTenant: string[];
  stale: string[];
  conflicts: string[];
  errors: string[];
  warnings: string[];
  canCompute: boolean;
  externalLiveAuthorizationProven: false;
  legacyScoreMutated: false;
};
const SOURCES: readonly V2Source[] = [
  "MICROSOFT_365", "GOOGLE_WORKSPACE", "LAB",
  "EXPOSURE", "BASELINE", "ASSETS",
];
const DOMAINS: readonly V2Domain[] = [
  "IDENTITY", "EMAIL", "WEB", "ENDPOINT",
  "BACKUP", "GOVERNANCE", "EXPOSURE",
];
const STATES: readonly V2State[] = [
  "OBSERVED", "DECLARED", "UNKNOWN", "ERROR",
];
const VERIFICATIONS: readonly V2Verification[] = [
  "TECHNICALLY_VERIFIED", "OPERATOR_DECLARED",
  "SYNTHETIC_FIXTURE", "NOT_VERIFIED",
];
const CONFIDENCE: readonly V2Confidence[] = [
  "HIGH", "MEDIUM", "LOW", "UNKNOWN",
];
export function supportedV2Sources() {
  return [...SOURCES];
}
export function supportedV2Domains() {
  return [...DOMAINS];
}
export function validV2Id(value: unknown) {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
export function validV2Hash(value: unknown) {
  return typeof value === "string" &&
    /^[a-f0-9]{64}$/.test(value);
}
export function validV2Time(value: unknown) {
  return typeof value === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}
export function validV2String(value: unknown, max = 400) {
  return typeof value === "string" &&
    value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value);
}
export function canonicalV2(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new Error("Nonfinite CyberScore number.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (value.length > 100000)
      throw new Error("CyberScore collection capacity exceeded.");
    return "[" + value.map(canonicalV2).join(",") + "]";
  }
  if (typeof value === "object" && value) {
    const keys = Object.keys(value).sort();
    if (keys.length > 100000)
      throw new Error("CyberScore object capacity exceeded.");
    return "{" + keys.map(key => {
      const element = (value as Record<string, unknown>)[key];
      if (element === undefined)
        throw new Error("Undefined CyberScore field.");
      return JSON.stringify(key) + ":" + canonicalV2(element);
    }).join(",") + "}";
  }
  throw new Error("Unsupported CyberScore JSON field.");
}
export function v2StableKey(...parts: string[]) {
  const normalized = parts.map(part => {
    if (!validV2String(part, 512))
      throw new Error("Invalid multi-source stable-key component.");
    return part.length + ":" + part;
  }).join("|");
  return normalized;
}
export function defaultV2Controls(): V2ControlSpec[] {
  const controls: Array<{
    id: string; domain: V2Domain; sources: V2Source[];
    weight: number; scope: V2ScopeKind; age: number;
    requirement: V2ControlSpec["requiredVerification"];
    criticality: V2ControlSpec["criticality"];
    title: string; description: string;
  }> = [
    { id: "IDENTITY_PRIVILEGED_MFA", domain: "IDENTITY",
      sources: ["MICROSOFT_365", "GOOGLE_WORKSPACE", "BASELINE"],
      weight: 16, scope: "ORGANIZATION", age: 7,
      requirement: "TECHNICAL", criticality: "CRITICAL",
      title: "Privileged MFA", description: "Privileged accounts have defensible MFA evidence." },
    { id: "IDENTITY_USER_INVENTORY", domain: "IDENTITY",
      sources: ["MICROSOFT_365", "GOOGLE_WORKSPACE", "BASELINE"],
      weight: 8, scope: "ORGANIZATION", age: 14,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Identity inventory", description: "Scoped identity population is explicitly observed." },
    { id: "IDENTITY_INACTIVE_ACCOUNTS", domain: "IDENTITY",
      sources: ["MICROSOFT_365", "GOOGLE_WORKSPACE", "BASELINE"],
      weight: 6, scope: "ORGANIZATION", age: 30,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Inactive accounts", description: "Account age and inactivity signals are observed." },
    { id: "IDENTITY_PRIVILEGED_ROLES", domain: "IDENTITY",
      sources: ["MICROSOFT_365", "GOOGLE_WORKSPACE", "BASELINE"],
      weight: 8, scope: "ORGANIZATION", age: 14,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Privileged role coverage", description: "Elevated privileges have traceable inventory." },
    { id: "EMAIL_DMARC", domain: "EMAIL",
      sources: ["MICROSOFT_365", "EXPOSURE"],
      weight: 9, scope: "DOMAIN", age: 14,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "DMARC observed", description: "DMARC evidence from authorized domain." },
    { id: "EMAIL_SPF", domain: "EMAIL",
      sources: ["MICROSOFT_365", "EXPOSURE"],
      weight: 7, scope: "DOMAIN", age: 14,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "SPF observed", description: "SPF evidence with freshness and scope." },
    { id: "EMAIL_DKIM", domain: "EMAIL",
      sources: ["MICROSOFT_365", "EXPOSURE"],
      weight: 7, scope: "DOMAIN", age: 14,
      requirement: "TECHNICAL", criticality: "NORMAL",
      title: "DKIM evidence", description: "Only verified selectors are counted." },
    { id: "WEB_TLS", domain: "WEB",
      sources: ["EXPOSURE"],
      weight: 8, scope: "DOMAIN", age: 7,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "TLS observation", description: "Authorized passive TLS metadata." },
    { id: "WEB_SECURITY_HEADERS", domain: "WEB",
      sources: ["EXPOSURE"],
      weight: 5, scope: "DOMAIN", age: 7,
      requirement: "TECHNICAL", criticality: "NORMAL",
      title: "HTTP headers", description: "Security header observations." },
    { id: "ENDPOINT_DEVICE_INVENTORY", domain: "ENDPOINT",
      sources: ["ASSETS", "BASELINE"],
      weight: 8, scope: "ORGANIZATION", age: 30,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Device inventory", description: "Declared device scope and provenance." },
    { id: "ENDPOINT_PATCH_POSTURE", domain: "ENDPOINT",
      sources: ["ASSETS", "BASELINE"],
      weight: 9, scope: "ORGANIZATION", age: 30,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Patch posture", description: "Evidence of patch status, not inferred safety." },
    { id: "ENDPOINT_PROTECTION", domain: "ENDPOINT",
      sources: ["BASELINE", "ASSETS"],
      weight: 8, scope: "ORGANIZATION", age: 30,
      requirement: "DECLARATION_ACCEPTABLE", criticality: "HIGH",
      title: "Endpoint protection", description: "Attested security-tool availability." },
    { id: "BACKUP_POLICY", domain: "BACKUP",
      sources: ["BASELINE"],
      weight: 8, scope: "ORGANIZATION", age: 90,
      requirement: "DECLARATION_ACCEPTABLE", criticality: "HIGH",
      title: "Backup policy", description: "Scope and owner of backup policy." },
    { id: "BACKUP_RESTORE_TEST", domain: "BACKUP",
      sources: ["BASELINE"],
      weight: 12, scope: "ORGANIZATION", age: 90,
      requirement: "TECHNICAL", criticality: "CRITICAL",
      title: "Restore rehearsal", description: "Actual tested backup restoration evidence." },
    { id: "GOVERNANCE_INCIDENT_PLAN", domain: "GOVERNANCE",
      sources: ["BASELINE"],
      weight: 7, scope: "ORGANIZATION", age: 180,
      requirement: "DECLARATION_ACCEPTABLE", criticality: "HIGH",
      title: "Incident response", description: "Documented plan for incident handling." },
    { id: "GOVERNANCE_SECURITY_TRAINING", domain: "GOVERNANCE",
      sources: ["BASELINE"],
      weight: 5, scope: "ORGANIZATION", age: 180,
      requirement: "DECLARATION_ACCEPTABLE", criticality: "NORMAL",
      title: "Awareness training", description: "Scoped security awareness evidence." },
    { id: "GOVERNANCE_ACCESS_REVIEWS", domain: "GOVERNANCE",
      sources: ["BASELINE", "MICROSOFT_365", "GOOGLE_WORKSPACE"],
      weight: 7, scope: "ORGANIZATION", age: 90,
      requirement: "DECLARATION_ACCEPTABLE", criticality: "HIGH",
      title: "Access reviews", description: "Evidence of periodic access authorization checks." },
    { id: "EXPOSURE_ASSET_DISCOVERY", domain: "EXPOSURE",
      sources: ["ASSETS", "EXPOSURE"],
      weight: 8, scope: "ORGANIZATION", age: 30,
      requirement: "TECHNICAL", criticality: "HIGH",
      title: "Passive asset discovery", description: "Explicitly inventoried or authorized externally exposed assets." },
    { id: "EXPOSURE_VULNERABILITY", domain: "EXPOSURE",
      sources: ["ASSETS", "EXPOSURE"],
      weight: 10, scope: "ORGANIZATION", age: 30,
      requirement: "TECHNICAL", criticality: "CRITICAL",
      title: "Vulnerability exposure", description: "Observed evidence of vulnerable software without exploitation claims." },
  ];
  return controls.map(row => ({
    schema: "cyberpilot.multisource.control.v2",
    id: row.id, domain: row.domain,
    scope: row.scope, weight: row.weight,
    criticality: row.criticality,
    acceptedSources: [...row.sources],
    requiredVerification: row.requirement,
    maxAgeDays: row.age, applicability: "REQUIRED",
    title: row.title, description: row.description,
  }));
}
export function validateV2Control(
  row: V2ControlSpec,
): string[] {
  const issues: string[] = [];
  if (row.schema !== "cyberpilot.multisource.control.v2")
    issues.push("CONTROL_SCHEMA");
  if (!validV2Id(row.id)) issues.push("CONTROL_ID");
  if (!DOMAINS.includes(row.domain)) issues.push("CONTROL_DOMAIN");
  if (!["ORGANIZATION", "DOMAIN", "USER", "DEVICE",
    "SERVICE", "WORKLOAD"].includes(row.scope))
    issues.push("CONTROL_SCOPE");
  if (!Number.isSafeInteger(row.weight) ||
      row.weight < 1 || row.weight > 100)
    issues.push("CONTROL_WEIGHT");
  if (!Number.isSafeInteger(row.maxAgeDays) ||
      row.maxAgeDays < 1 || row.maxAgeDays > 3650)
    issues.push("CONTROL_FRESHNESS");
  if (!row.acceptedSources?.length ||
      row.acceptedSources.some(x => !SOURCES.includes(x)) ||
      new Set(row.acceptedSources).size !== row.acceptedSources.length)
    issues.push("CONTROL_SOURCES");
  if (!["TECHNICAL", "DECLARATION_ACCEPTABLE"]
    .includes(row.requiredVerification))
    issues.push("CONTROL_VERIFICATION");
  if (!["CRITICAL", "HIGH", "NORMAL"].includes(row.criticality))
    issues.push("CONTROL_CRITICALITY");
  if (!["REQUIRED", "OPTIONAL"].includes(row.applicability))
    issues.push("CONTROL_APPLICABILITY");
  if (!validV2String(row.title) ||
      !validV2String(row.description, 1200))
    issues.push("CONTROL_DESCRIPTION");
  return issues;
}
export function validateV2Evidence(
  row: V2Evidence, organizationId: string,
): string[] {
  const issues: string[] = [];
  if (row.schema !== "cyberpilot.multisource.evidence.v2")
    issues.push("EVIDENCE_SCHEMA");
  if (!validV2Id(row.organizationId) ||
      row.organizationId !== organizationId)
    issues.push("CROSS_TENANT");
  if (!validV2Id(row.evidenceId))
    issues.push("EVIDENCE_ID");
  if (!SOURCES.includes(row.source) ||
      !DOMAINS.includes(row.domain))
    issues.push("EVIDENCE_SOURCE_DOMAIN");
  if (!validV2Id(row.controlId))
    issues.push("EVIDENCE_CONTROL");
  if (!validV2String(row.scope, 512) ||
      !["ORGANIZATION", "DOMAIN", "USER", "DEVICE",
        "SERVICE", "WORKLOAD"].includes(row.scopeKind))
    issues.push("EVIDENCE_SCOPE");
  if (!validV2Hash(row.subjectHash) ||
      !validV2Hash(row.sourceDigest))
    issues.push("EVIDENCE_SOURCE_HASH");
  if (!STATES.includes(row.state) ||
      !CONFIDENCE.includes(row.confidence) ||
      !VERIFICATIONS.includes(row.verification))
    issues.push("EVIDENCE_STATE");
  if (!validV2Time(row.checkedAt) ||
      row.observedAt !== null && !validV2Time(row.observedAt) ||
      row.validUntil !== null && !validV2Time(row.validUntil))
    issues.push("EVIDENCE_TIME");
  if (row.state === "OBSERVED" && row.observedAt === null)
    issues.push("OBSERVED_NEEDS_TIMESTAMP");
  if (row.state !== "OBSERVED" &&
      row.verification === "TECHNICALLY_VERIFIED")
    issues.push("UNOBSERVED_VERIFIED");
  if (row.state === "DECLARED" &&
      row.verification === "TECHNICALLY_VERIFIED")
    issues.push("DECLARED_NOT_TECHNICAL");
  if (!["COMPLETE", "PARTIAL", "DENIED",
    "UNKNOWN"].includes(row.sourceCoverage))
    issues.push("EVIDENCE_COVERAGE");
  if (!validV2String(row.authority, 256) ||
      !validV2String(row.sourceReference, 512))
    issues.push("EVIDENCE_PROVENANCE");
  if (!row.details || typeof row.details !== "object" ||
      Array.isArray(row.details) ||
      Object.keys(row.details).length > 60)
    issues.push("EVIDENCE_DETAILS");
  else for (const [key, value] of Object.entries(row.details)) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(key) ||
        /(email|phone|password|token|secret|credential|ipaddress)/i
          .test(key) ||
        typeof value === "string" && !validV2String(value, 300) ||
        typeof value === "number" && !Number.isFinite(value) ||
        value !== null &&
          !["string", "number", "boolean"].includes(typeof value))
      issues.push("EVIDENCE_PII_OR_INVALID_DETAIL");
  }
  if (row.rawPersonalDataStored || row.providerAccountModified ||
      row.customerApprovalInferred)
    issues.push("UNSUPPORTED_LIVE_ASSURANCE");
  return issues;
}
export function validateV2Finding(
  row: V2Finding, organizationId: string,
): string[] {
  const issues: string[] = [];
  if (row.schema !== "cyberpilot.multisource.finding.v2")
    issues.push("FINDING_SCHEMA");
  if (row.organizationId !== organizationId ||
      !validV2Id(row.organizationId))
    issues.push("FINDING_CROSS_TENANT");
  if (!validV2Id(row.findingId) ||
      !validV2Id(row.ruleId) ||
      !validV2Id(row.controlId))
    issues.push("FINDING_ID");
  if (!DOMAINS.includes(row.domain) ||
      !SOURCES.includes(row.source))
    issues.push("FINDING_SOURCE");
  if (!validV2String(row.scope, 512) ||
      !validV2Hash(row.subjectHash))
    issues.push("FINDING_SCOPE");
  if (!["CRITICAL", "HIGH", "MEDIUM",
    "LOW", "INFO", "UNKNOWN"].includes(row.severity) ||
      !["POTENTIAL_RISK", "REQUIRES_REVIEW",
        "UNKNOWN"].includes(row.state))
    issues.push("FINDING_STATUS");
  if (!CONFIDENCE.includes(row.confidence) ||
      !validV2Time(row.observedAt))
    issues.push("FINDING_TIMESTAMP");
  if (!row.evidenceIds?.length ||
      new Set(row.evidenceIds).size !== row.evidenceIds.length ||
      row.evidenceIds.some(x => !validV2Id(x)))
    issues.push("FINDING_EVIDENCE");
  if (!validV2String(row.title, 400) ||
      !validV2String(row.explanation, 1000) ||
      !validV2String(row.remediation, 1000))
    issues.push("FINDING_RECOMMENDATION");
  if (row.autoRemediated || row.resolved || row.customerAccepted)
    issues.push("FINDING_UNVERIFIED_ACTION");
  return issues;
}
export function validateV2Scope(
  row: V2Scope, organizationId: string,
): string[] {
  const issues: string[] = [];
  if (row.organizationId !== organizationId)
    issues.push("SCOPE_CROSS_TENANT");
  if (!SOURCES.includes(row.source) ||
      !DOMAINS.includes(row.domain))
    issues.push("SCOPE_SOURCE");
  if (!validV2String(row.scope, 512) ||
      !["ORGANIZATION", "DOMAIN", "USER", "DEVICE",
        "SERVICE", "WORKLOAD"].includes(row.scopeKind))
    issues.push("SCOPE_NAME");
  if (!validV2Time(row.checkedAt) ||
      row.validUntil !== null && !validV2Time(row.validUntil))
    issues.push("SCOPE_TIME");
  if (!validV2Hash(row.sourceDigest))
    issues.push("SCOPE_DIGEST");
  if (!["COMPLETE", "PARTIAL", "PERMISSION_DENIED",
    "ERROR", "UNASSESSED"].includes(row.status))
    issues.push("SCOPE_STATUS");
  if (row.expectedSubjects !== null &&
      (!Number.isSafeInteger(row.expectedSubjects) ||
       row.expectedSubjects < 0))
    issues.push("SCOPE_EXPECTED");
  if (row.observedSubjects !== null &&
      (!Number.isSafeInteger(row.observedSubjects) ||
       row.observedSubjects < 0))
    issues.push("SCOPE_OBSERVED");
  if (row.totalPages !== null &&
      (!Number.isSafeInteger(row.totalPages) ||
       row.totalPages < 1))
    issues.push("SCOPE_PAGES");
  if (row.pagesObserved !== null &&
      (!Number.isSafeInteger(row.pagesObserved) ||
       row.pagesObserved < 0))
    issues.push("SCOPE_READ");
  if (!Array.isArray(row.errors) ||
      row.errors.length > 100 ||
      row.errors.some(x => !validV2String(x, 256)))
    issues.push("SCOPE_ERRORS");
  if (typeof row.customerTenantAuthenticated !== "boolean" ||
      typeof row.scopeAuthenticityVerified !== "boolean")
    issues.push("SCOPE_VERIFICATION");
  return issues;
}
export function validateV2Manifest(
  manifest: V2Manifest,
): V2Validation {
  const errors: string[] = [];
  const crossTenant: string[] = [];
  const duplicates: string[] = [];
  const conflicts: string[] = [];
  const stale: string[] = [];
  const warnings: string[] = [];
  if (manifest.schema !== "cyberpilot.multisource.manifest.v2" ||
      manifest.modelId !== "cyberpilot.multisource.v2" ||
      manifest.modelRevision !== 1)
    errors.push("MANIFEST_SCHEMA_OR_MODEL");
  if (!validV2Id(manifest.organizationId) ||
      !validV2Id(manifest.snapshotId) ||
      !validV2Time(manifest.evaluatedAt))
    errors.push("MANIFEST_IDENTITY_OR_TIME");
  if (manifest.historicalCyberScoreTouched ||
      manifest.externalLiveConsentVerified ||
      manifest.customerApprovalAttested)
    errors.push("MANIFEST_FALSE_APPROVAL_OR_LEGACY_MUTATION");
  if (!Array.isArray(manifest.expectedControls) ||
      manifest.expectedControls.length > 5000 ||
      !Array.isArray(manifest.evidence) ||
      manifest.evidence.length > 50000 ||
      !Array.isArray(manifest.findings) ||
      manifest.findings.length > 50000 ||
      !Array.isArray(manifest.scopes) ||
      manifest.scopes.length > 50000)
    errors.push("MANIFEST_CAPACITY");
  const controls = manifest.expectedControls ?? [];
  const evidence = manifest.evidence ?? [];
  const findings = manifest.findings ?? [];
  const scopes = manifest.scopes ?? [];
  const identifiers = new Set<string>();
  for (const control of controls) {
    const issues = validateV2Control(control);
    if (issues.length) errors.push(
      "CONTROL_" + control.id + ":" + issues.join("|"));
    if (identifiers.has(control.id))
      duplicates.push("DUPLICATE_CONTROL_" + control.id);
    identifiers.add(control.id);
  }
  const seenEvidence = new Set<string>();
  for (const item of evidence) {
    const issues = validateV2Evidence(item, manifest.organizationId);
    if (issues.length) errors.push(
      "EVIDENCE_" + item.evidenceId + ":" + issues.join("|"));
    if (item.organizationId !== manifest.organizationId)
      crossTenant.push(item.evidenceId);
    if (seenEvidence.has(item.evidenceId))
      duplicates.push("DUPLICATE_EVIDENCE_" + item.evidenceId);
    seenEvidence.add(item.evidenceId);
    const control = controls.find(c => c.id === item.controlId);
    if (!control || control.domain !== item.domain ||
        control.scope !== item.scopeKind ||
        !control.acceptedSources.includes(item.source))
      conflicts.push("EVIDENCE_CONTROL_MISMATCH_" + item.evidenceId);
    if (item.checkedAt > manifest.evaluatedAt ||
        item.observedAt !== null &&
          item.observedAt > manifest.evaluatedAt)
      stale.push("EVIDENCE_IN_FUTURE_" + item.evidenceId);
  }
  const seenFindings = new Set<string>();
  for (const item of findings) {
    const issues = validateV2Finding(item, manifest.organizationId);
    if (issues.length) errors.push(
      "FINDING_" + item.findingId + ":" + issues.join("|"));
    if (item.organizationId !== manifest.organizationId)
      crossTenant.push(item.findingId);
    if (seenFindings.has(item.findingId))
      duplicates.push("DUPLICATE_FINDING_" + item.findingId);
    seenFindings.add(item.findingId);
    if (!controls.some(c => c.id === item.controlId &&
      c.domain === item.domain))
      conflicts.push("FINDING_CONTROL_MISMATCH_" + item.findingId);
    if (item.evidenceIds.some(id => !seenEvidence.has(id)))
      conflicts.push("FINDING_EVIDENCE_MISSING_" + item.findingId);
  }
  for (const item of scopes) {
    const issues = validateV2Scope(item, manifest.organizationId);
    if (issues.length) errors.push(
      "SCOPE_" + item.source + ":" + issues.join("|"));
    if (item.organizationId !== manifest.organizationId)
      crossTenant.push("SCOPE_" + item.source);
  }
  if (!Array.isArray(manifest.expectedDomains) ||
      manifest.expectedDomains.some(d => !DOMAINS.includes(d)) ||
      new Set(manifest.expectedDomains).size !==
        manifest.expectedDomains.length)
    errors.push("EXPECTED_DOMAINS_INVALID");
  if (!Array.isArray(manifest.sourceDigests) ||
      manifest.sourceDigests.some(x => !validV2Hash(x)))
    errors.push("SOURCE_DIGEST_MANIFEST_INVALID");
  for (const item of evidence) {
    if (!manifest.sourceDigests.includes(item.sourceDigest))
      conflicts.push("SOURCE_NOT_IN_MANIFEST_" + item.evidenceId);
  }
  if (evidence.some(x => x.state === "DECLARED"))
    warnings.push("Declarations are not provider technical verification.");
  if (evidence.some(x => x.verification === "SYNTHETIC_FIXTURE"))
    warnings.push("A fixture does not authenticate an external tenant.");
  if (evidence.some(x => x.state === "UNKNOWN" ||
      x.state === "ERROR"))
    warnings.push("Unobserved controls cannot be considered healthy.");
  const valid = errors.length === 0 &&
    crossTenant.length === 0 &&
    duplicates.length === 0 &&
    conflicts.length === 0 &&
    stale.length === 0;
  return {
    valid, organizationId: manifest.organizationId ?? null,
    checked: evidence.length + findings.length + scopes.length +
      controls.length,
    accepted: valid ? evidence.length : 0,
    rejected: valid ? 0 : errors.length +
      crossTenant.length + duplicates.length + conflicts.length +
      stale.length,
    duplicates, crossTenant, stale, conflicts, errors,
    warnings, canCompute: valid,
    externalLiveAuthorizationProven: false,
    legacyScoreMutated: false,
  };
}
export function emptyV2Manifest(
  organizationId: string,
  evaluatedAt: string, snapshotId: string,
  controls: V2ControlSpec[] = defaultV2Controls(),
): V2Manifest {
  if (!validV2Id(organizationId) ||
      !validV2Time(evaluatedAt) || !validV2Id(snapshotId))
    throw new Error("Invalid initial multi-source assessment scope.");
  return {
    schema: "cyberpilot.multisource.manifest.v2",
    organizationId, evaluatedAt, snapshotId,
    modelId: "cyberpilot.multisource.v2",
    modelRevision: 1,
    expectedDomains: [...new Set(controls.map(c => c.domain))],
    expectedControls: controls,
    evidence: [], findings: [], scopes: [],
    sourceDigests: [],
    historicalCyberScoreTouched: false,
    externalLiveConsentVerified: false,
    customerApprovalAttested: false,
  };
}
