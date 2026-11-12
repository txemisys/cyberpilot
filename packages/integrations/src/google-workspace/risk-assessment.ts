import { createHash, timingSafeEqual } from "node:crypto";
import {
  CAPABILITIES, buildEvidenceRecords, verifyObservation,
  subjectHash,
  type GoogleCapability, type GoogleEvidenceRecord,
  type GoogleDirectoryObservation, type GoogleFindingSeverity,
} from "./directory-contract";

export type GoogleRuleId =
  "SUPERADMIN_2SV_NOT_ENROLLED" |
  "SUPERADMIN_2SV_NOT_ENFORCED" |
  "SUPERADMIN_SUSPENDED_CONFLICT" |
  "DELEGATED_ADMIN_2SV_NOT_ENROLLED" |
  "USER_2SV_NOT_ENROLLED" |
  "USER_2SV_ENFORCEMENT_MISSING" |
  "STALE_ACTIVE_IDENTITY" |
  "DOMAIN_UNVERIFIED" |
  "ADMIN_AUDIT_UNAVAILABLE" |
  "LOGIN_AUDIT_UNAVAILABLE" |
  "DIRECTORY_PARTIAL" |
  "UNKNOWN_MFA_SIGNAL" |
  "UNKNOWN_ADMIN_STATUS" |
  "SUSPENSION_STATUS_UNKNOWN" |
  "SOURCE_FIXTURE_ONLY";
export type GoogleFindingStatus =
  "POTENTIAL_RISK" | "NEEDS_REVIEW" |
  "INSUFFICIENT_EVIDENCE";
export type GoogleFinding = {
  schema: "cyberpilot.google.finding.v1";
  id: string;
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  ruleId: GoogleRuleId;
  subjectHash: string;
  status: GoogleFindingStatus;
  severity: GoogleFindingSeverity;
  title: string;
  explanation: string;
  remediation: string;
  verification: string;
  evidenceIds: string[];
  sourceDigest: string;
  observedAt: string | null;
  confidence: "MEDIUM" | "LOW" | "UNKNOWN";
  scope: "IDENTITY" | "DOMAIN" | "TENANT";
  recordedNotProvenExploitable: true;
  providerLicenseNotCertified: true;
  automaticallyRemediated: false;
  actualProviderValidated: false;
};
export type GoogleCoverageItem = {
  capability: GoogleCapability;
  status: "COMPLETE_FIXTURE" | "OBSERVED_IN_ADAPTER" |
    "NOT_VERIFIED" | "PARTIAL" | "PERMISSION_BLOCKED" |
    "NOT_LICENSED" | "UNKNOWN";
  usefulSignals: number;
  unknownSignals: number;
  sourceCount: number;
  scoreEligible: boolean;
  fullCoverageClaimed: false;
};
export type GoogleScore = {
  schema: "cyberpilot.google.score.preview.v1";
  score: number | null;
  model: "GOOGLE_OFFLINE_PREVIEW_NOT_CYBERSCORE";
  rulesEvaluated: number;
  possibleRiskRules: number;
  unknownRiskRules: number;
  baselineWithoutGoogle: "NOT_COMPUTED";
  sourceCoveragePercent: number;
  confidence: "LOW" | "INSUFFICIENT";
  healthyLabelAllowed: false;
  tenantSecuredClaimed: false;
  cyberScoreUpdated: false;
  sourceIsSynthetic: boolean;
  comparableWithM365ByCoverageOnly: true;
  normalizedAcrossProvidersWithoutCalibration: false;
};
export type GoogleRiskAssessment = {
  schema: "cyberpilot.google.risk.assessment.v1";
  organizationId: string;
  sourceDigest: string;
  assessedAt: string;
  source: GoogleDirectoryObservation["source"];
  evidence: GoogleEvidenceRecord[];
  findings: GoogleFinding[];
  coverage: GoogleCoverageItem[];
  score: GoogleScore;
  counts: {
    usersSeen: number;
    domainsSeen: number;
    orgUnitsSeen: number;
    auditEventsSeen: number;
    superadminsObserved: number;
    delegatedAdminsObserved: number;
    usersWithUnknownMfa: number;
    possibleRisks: number;
    reviewItems: number;
    unknownFindings: number;
    unavailableCapabilities: number;
    incompleteCapabilities: number;
  };
  topActions: Array<{
    rank: number;
    findingId: string;
    severity: GoogleFindingSeverity;
    description: string;
    nextStep: string;
    requiresAdministratorApproval: true;
    automaticActionExecuted: false;
  }>;
  digest: string;
  limitations: string[];
  providerContactedByAssessment: false;
  accountWrites: 0;
  customerLegalApproval: false;
  productSignoffGranted: false;
  liveProviderVerified: false;
  cybersecurityCertified: false;
};
export type GoogleAssessmentPolicy = {
  staleAfterDays: number;
  includeSuspended: boolean;
  includeNonAdmin2Sv: boolean;
  maximumFindings: number;
  referenceDate: string;
};
const limitations = [
  "Findings are cautious interpretations of Directory/Reports attributes; they do not prove account compromise.",
  "The source can be entirely synthetic, and no customer tenant is authenticated by this assessment.",
  "Unavailable licensing or scope may hide MFA/Reports details; UNKNOWN cannot be treated as healthy.",
  "The preview score is not the canonical multitenant CyberScore and does not replace it.",
  "An inactive timestamp alone is not evidence of account compromise or abuse.",
  "Tenant-wide counts are only as complete as the paginated provider observation.",
  "No administrator actions, account modifications or OAuth consent changes are performed.",
  "Manual operational approvals and real provider validation remain independent.",
];
const severityOrder: Record<GoogleFindingSeverity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2,
  LOW: 3, INFO: 4, UNKNOWN: 5,
};
const ruleMeta: Record<GoogleRuleId, {
  title: string; explanation: string;
  remediation: string; verification: string;
  severity: GoogleFindingSeverity;
  scope: GoogleFinding["scope"];
}> = {
  SUPERADMIN_2SV_NOT_ENROLLED: {
    title: "Superadministrator not enrolled in 2-step verification",
    explanation: "The Directory attribute reports no 2SV enrollment for an observed superadministrator.",
    remediation: "Confirm applicability, emergency-access requirements and enroll appropriate 2SV under administrator change control.",
    verification: "Re-read the specific Directory enrollment attribute and corroborate with the authorized administrator.",
    severity: "HIGH", scope: "IDENTITY",
  },
  SUPERADMIN_2SV_NOT_ENFORCED: {
    title: "Superadministrator 2-step enforcement not indicated",
    explanation: "Directory reports no enforced 2SV; organizational enforcement policies have not been independently checked.",
    remediation: "Review Google Workspace policies for privileged accounts and implement approved enforcement.",
    verification: "Check applicable policy and Directory enforcement attributes with authorized evidence.",
    severity: "HIGH", scope: "IDENTITY",
  },
  SUPERADMIN_SUSPENDED_CONFLICT: {
    title: "Suspended superadministrator still marked privileged",
    explanation: "Directory flags both suspension and superadministrator status; this may be intentional.",
    remediation: "Verify actual privileges and organizational identity lifecycle requirements before changes.",
    verification: "Confirm relevant administrator role assignments and account status separately.",
    severity: "LOW", scope: "IDENTITY",
  },
  DELEGATED_ADMIN_2SV_NOT_ENROLLED: {
    title: "Delegated administrator not enrolled in 2SV",
    explanation: "The delegated-administrator attribute is present but its user shows no 2SV enrollment.",
    remediation: "Confirm delegated privileges and require 2SV where the account policy applies.",
    verification: "Review admin roles and 2SV status after an authorized policy change.",
    severity: "HIGH", scope: "IDENTITY",
  },
  USER_2SV_NOT_ENROLLED: {
    title: "User not enrolled in 2SV",
    explanation: "This is a directory enrollment observation, not a complete assessment of sign-in security.",
    remediation: "Review the user's eligibility and approved 2SV rollout requirements.",
    verification: "Reassess directory enrollment and applicable enforcement configuration.",
    severity: "MEDIUM", scope: "IDENTITY",
  },
  USER_2SV_ENFORCEMENT_MISSING: {
    title: "2SV enforcement not indicated",
    explanation: "The user is enrolled, but Directory enforcement is recorded as false.",
    remediation: "Review whether the appropriate OU/user policy requires 2SV enforcement.",
    verification: "Check policy scope, enforcement and enrollment in subsequent observation.",
    severity: "LOW", scope: "IDENTITY",
  },
  STALE_ACTIVE_IDENTITY: {
    title: "Active identity with an old sign-in timestamp",
    explanation: "The Directory last-login timestamp is older than the declared review threshold.",
    remediation: "Confirm the account's role, use, exemptions and owner before any lifecycle action.",
    verification: "Corroborate login activity and identity owner; do not auto-suspend.",
    severity: "MEDIUM", scope: "IDENTITY",
  },
  DOMAIN_UNVERIFIED: {
    title: "Directory lists a domain without verified status",
    explanation: "The returned domain verification flag is false.",
    remediation: "Confirm the domain is expected and inspect its ownership verification state.",
    verification: "Re-read domain verification status from an authorized source.",
    severity: "MEDIUM", scope: "DOMAIN",
  },
  ADMIN_AUDIT_UNAVAILABLE: {
    title: "Admin audit visibility unavailable",
    explanation: "The report feed is missing, truncated, denied or unsupported by the current license.",
    remediation: "Investigate minimum scopes, retention, edition and API availability.",
    verification: "Confirm a complete bounded Admin activity report with correct permissions.",
    severity: "UNKNOWN", scope: "TENANT",
  },
  LOGIN_AUDIT_UNAVAILABLE: {
    title: "Login audit visibility unavailable",
    explanation: "Login activity has not been completely observed.",
    remediation: "Review Reports API scope and organization retention/edition limitations.",
    verification: "Confirm an authorized, complete bounded Login activity snapshot.",
    severity: "UNKNOWN", scope: "TENANT",
  },
  DIRECTORY_PARTIAL: {
    title: "Directory inventory is incomplete",
    explanation: "An essential directory capability could not be completely inspected.",
    remediation: "Retry failed pages, investigate permissions and verify the expected customer scope.",
    verification: "Complete the snapshot without truncation or hidden pages.",
    severity: "UNKNOWN", scope: "TENANT",
  },
  UNKNOWN_MFA_SIGNAL: {
    title: "2SV evidence is unknown for an identity",
    explanation: "The provider did not expose sufficient MFA attributes to classify this user.",
    remediation: "Verify Directory field permissions, coverage and actual applicable policy.",
    verification: "Acquire authoritative enrolled/enforced attributes without assuming a healthy state.",
    severity: "UNKNOWN", scope: "IDENTITY",
  },
  UNKNOWN_ADMIN_STATUS: {
    title: "Privilege status is unavailable",
    explanation: "Directory does not provide a definitive observed administrator attribute.",
    remediation: "Inspect role assignment from an appropriate read-only source.",
    verification: "Reconcile user and role attributes and note any unsupported role type.",
    severity: "UNKNOWN", scope: "IDENTITY",
  },
  SUSPENSION_STATUS_UNKNOWN: {
    title: "Identity suspension state is unknown",
    explanation: "No reliable status is present in the observed Directory user record.",
    remediation: "Verify user state and API field completeness.",
    verification: "Reassess the user with sufficient Directory visibility.",
    severity: "UNKNOWN", scope: "IDENTITY",
  },
  SOURCE_FIXTURE_ONLY: {
    title: "Only fixture-derived identity evidence is available",
    explanation: "This assessment was generated from offline simulated data.",
    remediation: "Obtain real administrator consent and run a separate authorized provider check when operationally required.",
    verification: "Never attest provider LIVE from synthetic responses.",
    severity: "UNKNOWN", scope: "TENANT",
  },
};
function invalid(message: string): never {
  throw new Error("Invalid Google risk assessment: " + message);
}
function equal(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function parseGoogleAssessmentPolicy(
  raw: unknown = {}, now = new Date(),
): GoogleAssessmentPolicy {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    invalid("Policy must be a record.");
  const v = raw as Record<string, unknown>;
  if (Object.keys(v).some(k => !["staleAfterDays",
    "includeSuspended", "includeNonAdmin2Sv", "maximumFindings",
    "referenceDate"].includes(k)))
    invalid("Unrecognized assessment policy field.");
  const staleAfterDays = v.staleAfterDays ?? 90;
  const maximumFindings = v.maximumFindings ?? 5000;
  if (typeof staleAfterDays !== "number" ||
      !Number.isSafeInteger(staleAfterDays) ||
      staleAfterDays < 1 || staleAfterDays > 3650)
    invalid("staleness threshold out of range.");
  if (typeof maximumFindings !== "number" ||
      !Number.isSafeInteger(maximumFindings) ||
      maximumFindings < 1 || maximumFindings > 10000)
    invalid("finding cap out of range.");
  for (const name of ["includeSuspended", "includeNonAdmin2Sv"])
    if (v[name] !== undefined && typeof v[name] !== "boolean")
      invalid("Invalid boolean option " + name + ".");
  const rawDate = v.referenceDate ?? now.toISOString();
  if (typeof rawDate !== "string" ||
      !Number.isFinite(Date.parse(rawDate)) ||
      !/^\d{4}-\d\d-\d\dT/.test(rawDate))
    invalid("Invalid reference clock.");
  return {
    staleAfterDays, maximumFindings,
    includeSuspended: v.includeSuspended === true,
    includeNonAdmin2Sv: v.includeNonAdmin2Sv === true,
    referenceDate: new Date(rawDate).toISOString(),
  };
}
export function classifyGoogleCoverage(
  observation: GoogleDirectoryObservation,
  evidence: GoogleEvidenceRecord[],
): GoogleCoverageItem[] {
  return CAPABILITIES.map(capability => {
    const entitlement = observation.coverage[capability];
    const failure = observation.failures.some(f =>
      f.capability === capability);
    const truncated = observation.truncation[capability];
    const matching = evidence.filter(e => e.capability === capability);
    const usefulSignals = matching.filter(e =>
      e.state === "OBSERVED").length;
    const unknownSignals = matching.filter(e =>
      e.state === "UNKNOWN" || e.state === "ERROR").length;
    let status: GoogleCoverageItem["status"] = "UNKNOWN";
    if (entitlement === "REQUIRES_PERMISSION")
      status = "PERMISSION_BLOCKED";
    else if (entitlement === "NOT_AVAILABLE")
      status = "NOT_LICENSED";
    else if (failure || truncated)
      status = "PARTIAL";
    else if (entitlement === "AVAILABLE")
      status = observation.source === "SYNTHETIC_FIXTURE" ?
        "COMPLETE_FIXTURE" : "OBSERVED_IN_ADAPTER";
    return {
      capability, status, usefulSignals, unknownSignals,
      sourceCount: matching.length,
      scoreEligible: !failure && !truncated &&
        entitlement === "AVAILABLE" &&
        observation.source !== "SYNTHETIC_FIXTURE" &&
        matching.length > 0,
      fullCoverageClaimed: false,
    };
  });
}
export function buildGooglePreviewScore(
  observation: GoogleDirectoryObservation,
  findings: GoogleFinding[],
  coverage: GoogleCoverageItem[],
): GoogleScore {
  const usable = coverage.filter(c => c.scoreEligible);
  const meaningful = findings.filter(f =>
    f.status === "POTENTIAL_RISK");
  const unknowns = findings.filter(f =>
    f.status === "INSUFFICIENT_EVIDENCE");
  const deductions = meaningful.reduce((score, f) => score +
    ({ CRITICAL: 20, HIGH: 13, MEDIUM: 6,
       LOW: 2, INFO: 0, UNKNOWN: 0 }[f.severity]), 0);
  const complete = usable.length === CAPABILITIES.length &&
    observation.source !== "SYNTHETIC_FIXTURE" &&
    observation.users.length > 0 &&
    unknowns.length === 0;
  const percent = Math.round(100 * usable.length / CAPABILITIES.length);
  // A partial score has misleading semantics, so never emit one.
  // Even a full technical preview remains distinct from CyberScore.
  return {
    schema: "cyberpilot.google.score.preview.v1",
    score: complete ? Math.max(0, 100 - deductions) : null,
    model: "GOOGLE_OFFLINE_PREVIEW_NOT_CYBERSCORE",
    rulesEvaluated: findings.length,
    possibleRiskRules: meaningful.length,
    unknownRiskRules: unknowns.length,
    baselineWithoutGoogle: "NOT_COMPUTED",
    sourceCoveragePercent: percent,
    confidence: complete ? "LOW" : "INSUFFICIENT",
    healthyLabelAllowed: false, tenantSecuredClaimed: false,
    cyberScoreUpdated: false,
    sourceIsSynthetic: observation.source === "SYNTHETIC_FIXTURE",
    comparableWithM365ByCoverageOnly: true,
    normalizedAcrossProvidersWithoutCalibration: false,
  };
}
function has(value: unknown): value is boolean {
  return typeof value === "boolean";
}
function statusFor(rule: GoogleRuleId): GoogleFindingStatus {
  return [
    "ADMIN_AUDIT_UNAVAILABLE", "LOGIN_AUDIT_UNAVAILABLE",
    "DIRECTORY_PARTIAL", "UNKNOWN_MFA_SIGNAL",
    "UNKNOWN_ADMIN_STATUS", "SUSPENSION_STATUS_UNKNOWN",
    "SOURCE_FIXTURE_ONLY",
  ].includes(rule) ? "INSUFFICIENT_EVIDENCE" :
    rule === "SUPERADMIN_SUSPENDED_CONFLICT" ?
      "NEEDS_REVIEW" : "POTENTIAL_RISK";
}
export function detectGoogleFindings(
  observation: GoogleDirectoryObservation,
  evidence: GoogleEvidenceRecord[],
  policy: GoogleAssessmentPolicy,
): GoogleFinding[] {
  const rows: GoogleFinding[] = [];
  const seen = new Set<string>();
  const reference = new Date(policy.referenceDate).getTime();
  const write = (ruleId: GoogleRuleId, subject: string,
    related: GoogleEvidenceRecord[]) => {
    const key = ruleId + ":" + subject;
    if (seen.has(key)) return;
    seen.add(key);
    const rule = ruleMeta[ruleId];
    const status = statusFor(ruleId);
    const identifier = hash({ organizationId: observation.organizationId,
      source: observation.digest, ruleId, subject });
    rows.push({
      schema: "cyberpilot.google.finding.v1",
      id: identifier, organizationId: observation.organizationId,
      provider: "GOOGLE_WORKSPACE", ruleId,
      subjectHash: subjectHash(observation.organizationId, subject),
      status, severity: rule.severity,
      title: rule.title, explanation: rule.explanation,
      remediation: rule.remediation, verification: rule.verification,
      evidenceIds: related.map(e => hash({
        control: e.controlId, subject: e.subjectHash,
        source: e.sourceReference,
      })),
      sourceDigest: observation.digest,
      observedAt: status === "INSUFFICIENT_EVIDENCE" ?
        null : observation.generatedAt,
      confidence: status === "POTENTIAL_RISK" ? "MEDIUM" :
        status === "NEEDS_REVIEW" ? "LOW" : "UNKNOWN",
      scope: rule.scope,
      recordedNotProvenExploitable: true,
      providerLicenseNotCertified: true,
      automaticallyRemediated: false,
      actualProviderValidated: false,
    });
  };
  const identityEvidence = (id: string) =>
    evidence.filter(e => e.scope === "IDENTITIES" &&
      e.subjectHash === subjectHash(observation.organizationId, id));
  for (const user of observation.users) {
    if (rows.length > policy.maximumFindings)
      invalid("Finding budget exceeded; cannot emit a truncated assessment.");
    const refs = identityEvidence(user.id);
    const active = user.suspended === false;
    if (user.suspended === null)
      write("SUSPENSION_STATUS_UNKNOWN", user.id, refs);
    if (!has(user.isAdmin))
      write("UNKNOWN_ADMIN_STATUS", user.id, refs);
    const privileged = user.isAdmin === true ||
      user.isDelegatedAdmin === true;
    if (user.isAdmin === true && user.suspended === true)
      write("SUPERADMIN_SUSPENDED_CONFLICT", user.id, refs);
    if (user.suspended === true && !policy.includeSuspended) continue;
    if (user.isEnrolledIn2Sv === null ||
        observation.coverage.USER_MFA_ATTRIBUTES !== "AVAILABLE" ||
        observation.truncation.USER_MFA_ATTRIBUTES)
      write("UNKNOWN_MFA_SIGNAL", user.id, refs);
    else if (user.isEnrolledIn2Sv === false) {
      if (user.isAdmin === true)
        write("SUPERADMIN_2SV_NOT_ENROLLED", user.id, refs);
      else if (user.isDelegatedAdmin === true)
        write("DELEGATED_ADMIN_2SV_NOT_ENROLLED", user.id, refs);
      else if (policy.includeNonAdmin2Sv)
        write("USER_2SV_NOT_ENROLLED", user.id, refs);
    }
    if (user.isEnforcedIn2Sv === false &&
        observation.coverage.USER_MFA_ATTRIBUTES === "AVAILABLE" &&
        !observation.truncation.USER_MFA_ATTRIBUTES) {
      if (user.isAdmin === true)
        write("SUPERADMIN_2SV_NOT_ENFORCED", user.id, refs);
      else if (policy.includeNonAdmin2Sv)
        write("USER_2SV_ENFORCEMENT_MISSING", user.id, refs);
    }
    if (active && user.lastLoginTime &&
        reference - new Date(user.lastLoginTime).getTime() >=
          policy.staleAfterDays * 86400000)
      write("STALE_ACTIVE_IDENTITY", user.id, refs);
    if (privileged && !active && user.suspended === null)
      write("SUSPENSION_STATUS_UNKNOWN", user.id, refs);
  }
  for (const domain of observation.domains)
    if (domain.verified === false)
      write("DOMAIN_UNVERIFIED", domain.domainName,
        evidence.filter(e => e.controlId === "GOOGLE_DOMAIN_VERIFICATION"));
  for (const [capability, rule] of [
    ["REPORTS_LOGIN", "LOGIN_AUDIT_UNAVAILABLE"],
    ["REPORTS_ADMIN", "ADMIN_AUDIT_UNAVAILABLE"],
  ] as const)
    if (observation.coverage[capability] !== "AVAILABLE" ||
        observation.truncation[capability] ||
        observation.failures.some(f => f.capability === capability))
      write(rule, capability,
        evidence.filter(e => e.capability === capability));
  for (const capability of [
    "DIRECTORY_USERS", "DIRECTORY_DOMAINS",
    "DIRECTORY_ORGANIZATION_UNITS",
  ] as const)
    if (observation.coverage[capability] !== "AVAILABLE" ||
        observation.truncation[capability] ||
        observation.failures.some(f => f.capability === capability))
      write("DIRECTORY_PARTIAL", capability,
        evidence.filter(e => e.capability === capability));
  if (observation.source === "SYNTHETIC_FIXTURE")
    write("SOURCE_FIXTURE_ONLY", "SYNTHETIC_FIXTURE", []);
  if (rows.length > policy.maximumFindings)
    invalid("Too many Google findings to return a complete assessment.");
  return rows.sort((a, b) =>
    severityOrder[a.severity] - severityOrder[b.severity] ||
    a.ruleId.localeCompare(b.ruleId) ||
    a.subjectHash.localeCompare(b.subjectHash));
}
export function assessGoogleWorkspace(
  observation: GoogleDirectoryObservation,
  rawPolicy: unknown = {},
  now = new Date(),
): GoogleRiskAssessment {
  if (!verifyObservation(observation).valid)
    invalid("Source observation digest is invalid.");
  const policy = parseGoogleAssessmentPolicy(rawPolicy, now);
  if (new Date(observation.generatedAt).getTime() >
      new Date(policy.referenceDate).getTime())
    invalid("Source evidence is later than evaluation time.");
  const evidence = buildEvidenceRecords(observation);
  const coverage = classifyGoogleCoverage(observation, evidence);
  const findings = detectGoogleFindings(observation, evidence, policy);
  const score = buildGooglePreviewScore(observation, findings, coverage);
  const counts = {
    usersSeen: observation.users.length,
    domainsSeen: observation.domains.length,
    orgUnitsSeen: observation.orgUnits.length,
    auditEventsSeen: observation.reports.length,
    superadminsObserved: observation.users.filter(u =>
      u.isAdmin === true).length,
    delegatedAdminsObserved: observation.users.filter(u =>
      u.isDelegatedAdmin === true).length,
    usersWithUnknownMfa: observation.users.filter(u =>
      u.isEnrolledIn2Sv === null ||
      observation.coverage.USER_MFA_ATTRIBUTES !== "AVAILABLE").length,
    possibleRisks: findings.filter(f =>
      f.status === "POTENTIAL_RISK").length,
    reviewItems: findings.filter(f =>
      f.status === "NEEDS_REVIEW").length,
    unknownFindings: findings.filter(f =>
      f.status === "INSUFFICIENT_EVIDENCE").length,
    unavailableCapabilities: coverage.filter(c =>
      c.status === "PERMISSION_BLOCKED" ||
      c.status === "NOT_LICENSED").length,
    incompleteCapabilities: coverage.filter(c =>
      !["COMPLETE_FIXTURE", "OBSERVED_IN_ADAPTER"]
        .includes(c.status)).length,
  };
  const topActions = findings.filter(f =>
    f.status !== "INSUFFICIENT_EVIDENCE")
    .slice(0, 20).map((f, index) => ({
      rank: index + 1, findingId: f.id,
      severity: f.severity,
      description: f.title, nextStep: f.remediation,
      requiresAdministratorApproval: true as const,
      automaticActionExecuted: false as const,
    }));
  const canonical = {
    schema: "cyberpilot.google.risk.assessment.v1" as const,
    organizationId: observation.organizationId,
    sourceDigest: observation.digest,
    assessedAt: policy.referenceDate,
    source: observation.source,
    evidence, findings, coverage, score, counts, topActions,
    providerContactedByAssessment: false as const,
    accountWrites: 0 as const,
    customerLegalApproval: false as const,
    productSignoffGranted: false as const,
    liveProviderVerified: false as const,
    cybersecurityCertified: false as const,
  };
  return { ...canonical, digest: hash(canonical), limitations };
}
export function verifyGoogleRiskAssessment(
  assessment: GoogleRiskAssessment,
) {
  const { digest: fingerprint, limitations: notes, ...canonical } = assessment;
  const issues: string[] = [];
  if (!equal(fingerprint, hash(canonical)))
    issues.push("Risk assessment was changed.");
  if (assessment.score.cyberScoreUpdated ||
      assessment.score.healthyLabelAllowed ||
      assessment.score.tenantSecuredClaimed ||
      assessment.providerContactedByAssessment ||
      assessment.accountWrites !== 0 ||
      assessment.liveProviderVerified ||
      assessment.cybersecurityCertified ||
      assessment.customerLegalApproval)
    issues.push("Assessment claims unsupported security or LIVE work.");
  if (assessment.findings.some(f =>
    f.automaticallyRemediated || f.actualProviderValidated ||
    f.organizationId !== assessment.organizationId ||
    f.sourceDigest !== assessment.sourceDigest))
    issues.push("Finding claims unsupported scope or action.");
  if (assessment.coverage.length !== CAPABILITIES.length ||
      assessment.score.sourceIsSynthetic !==
        (assessment.source === "SYNTHETIC_FIXTURE"))
    issues.push("Assessment coverage or source class inconsistent.");
  if (assessment.source === "SYNTHETIC_FIXTURE" &&
      assessment.score.score !== null)
    issues.push("Synthetic observations cannot produce posture scores.");
  if (assessment.counts.possibleRisks !== assessment.findings.filter(
    f => f.status === "POTENTIAL_RISK").length)
    issues.push("Risk count does not match evidence.");
  if (!Array.isArray(notes) || notes.length < 6)
    issues.push("Mandatory limitations missing.");
  return { valid: issues.length === 0, issues };
}
export function googleRemediationPlan(assessment: GoogleRiskAssessment) {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    invalid("Cannot create action plan from corrupted evidence.");
  return assessment.topActions.map((action, index) => ({
    ...action, sequence: index + 1,
    state: "PROPOSED_ONLY" as const,
    approvedByCustomer: false as const,
    executedByConnector: false as const,
    verificationCompleted: false as const,
    externalTicketCreated: false as const,
  }));
}
export function googleAssessmentManifest(assessment: GoogleRiskAssessment) {
  if (!verifyGoogleRiskAssessment(assessment).valid)
    invalid("Cannot export corrupted risk assessment.");
  return {
    schema: "cyberpilot.google.assessment.manifest.v1" as const,
    organizationId: assessment.organizationId,
    assessedAt: assessment.assessedAt,
    sourceDigest: assessment.sourceDigest,
    assessmentDigest: assessment.digest,
    evidenceCount: assessment.evidence.length,
    findingsCount: assessment.findings.length,
    unknownCount: assessment.counts.unknownFindings,
    source: assessment.source,
    providerAuthenticated: false as const,
    customerApproved: false as const,
    signatureVerified: false as const,
    fullCoverageAttested: false as const,
    canonicalCyberScoreModified: false as const,
  };
}
