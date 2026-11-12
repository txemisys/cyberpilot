import { createHash, timingSafeEqual } from "node:crypto";
import type { AcceptanceReport } from "./assets-offline-acceptance";

/** Internal consistency only. SHA-256 is not a signed external attestation. */
export type AcceptanceVerification = {
  schema: "cyberpilot.assets.offline.acceptance.verification.v1";
  valid: boolean;
  fingerprintValid: boolean;
  summaryValid: boolean;
  gateIdsUnique: boolean;
  caseIdsUnique: boolean;
  sourceConsistent: boolean;
  noMutations: boolean;
  manualAcceptanceExplicit: boolean;
  issues: string[];
  warnings: string[];
};
const gateIdentifiers = new Set([
  "INVENTORY_COMPLETE", "INSPECTION_COMPLETE", "MAPPING_COVERAGE",
  "NO_IMPLICIT_SAFE", "CANDIDATE_PROVENANCE", "REVIEW_CASE_PROVENANCE",
  "CASE_LIFECYCLE", "CHECKLIST_INTEGRITY", "TENANT_ISOLATION",
  "AUDIT_COVERAGE", "UNKNOWN_EVIDENCE", "AGE_POLICY",
]);
function equalDigest(a: string, b: string): boolean {
  return /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function verifyOfflineAcceptanceReport(report: AcceptanceReport):
  AcceptanceVerification {
  const { reportDigest, warnings, ...canonical } = report;
  const issues: string[] = [];
  const fingerprintValid = equalDigest(reportDigest, digest(canonical));
  if (!fingerprintValid) issues.push("Report fingerprint differs from its canonical content.");
  const uniqueGateIds = new Set(report.gates.map(row => row.id));
  const gateIdsUnique = uniqueGateIds.size === gateIdentifiers.size &&
    report.gates.every(row => gateIdentifiers.has(row.id));
  if (!gateIdsUnique) issues.push("Acceptance gate identifiers were omitted, duplicated or unexpected.");
  const uniqueCaseIds = new Set(report.cases.map(row => row.caseId));
  const caseIdsUnique = uniqueCaseIds.size === report.cases.length;
  if (!caseIdsUnique) issues.push("A review case appears multiple times in the acceptance report.");
  const summaryValid =
    report.scorecard.passed === report.gates.filter(x => x.level === "PASS").length &&
    report.scorecard.blocked === report.gates.filter(x => x.level === "BLOCK").length &&
    report.scorecard.advisory === report.gates.filter(x => x.level === "ADVISORY").length &&
    report.scorecard.casesEvaluated === report.cases.length &&
    report.scorecard.casesWithIssues === report.cases.filter(x => x.issues.length).length &&
    report.scorecard.totalIssues === report.cases.reduce((n, x) => n + x.issues.length, 0) &&
    report.acceptanceEligible === (report.scorecard.blocked === 0);
  if (!summaryValid) issues.push("Gate and case counts disagree with the acceptance scorecard.");
  const sourceConsistent =
    report.source.deviceCount >= 0 && report.source.queryCount >= 0 &&
    report.source.reviewCaseCount === report.cases.length &&
    report.source.auditCount <= report.cases.length &&
    report.cases.every(row => row.caseId && row.revision > 0);
  if (!sourceConsistent) issues.push("Evidence counts or case revisions are inconsistent.");
  const noMutations =
    report.databaseWrites === 0 && report.providerRequests === 0 &&
    report.findingsModified === false && report.cyberScoreModified === false;
  if (!noMutations) issues.push("Report incorrectly declares side effects.");
  const manualAcceptanceExplicit =
    report.manualAcceptanceStillRequired === true &&
    report.noExternalTenantsRequired === true;
  if (!manualAcceptanceExplicit)
    issues.push("Manual acceptance or external tenant limitations were omitted.");
  return {
    schema: "cyberpilot.assets.offline.acceptance.verification.v1",
    valid: issues.length === 0,
    fingerprintValid, summaryValid, gateIdsUnique,
    caseIdsUnique, sourceConsistent, noMutations,
    manualAcceptanceExplicit, issues,
    warnings: [
      "Digest verification detects local accidental tampering, not authorship or provenance authentication.",
      "A valid acceptance report is not an approval to merge or proof of endpoint security.",
      "Manual end-to-end review, policy signoff and live operational exclusions remain independent.",
    ],
  };
}
