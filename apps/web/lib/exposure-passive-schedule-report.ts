import { sha256V2, canonicalV2 } from "@cyberpilot/risk-engine";
import type { PassiveScheduleView } from
  "./exposure-passive-schedule-service";

export type PassiveScheduleSummary = {
  schema: "cyberpilot.exposure.passive.schedule.report.v1";
  organizationId: string;
  evaluatedAt: string;
  count: number;
  policyDigests: string[];
  byState: Record<string, number>;
  bySource: Record<string, number>;
  enabledForNetwork: 0;
  verifiedLegalConsent: 0;
  pausedOrDisabled: number;
  revoked: number;
  configuredDnsQuota: number;
  configuredTlsQuota: number;
  configuredHttpQuota: number;
  unansweredAuthorizationQuestions: string[];
  domainRows: Array<{
    domain: string;
    revision: number;
    state: string;
    sources: string[];
    nextEligibleAt: string | null;
    policyDigest: string;
    mayScanAutomatically: false;
    independentlyVerifiedLegalConsent: false;
    technicalRiskScore: null;
  }>;
  limitations: string[];
  noNetworkRequests: true;
  noLegalApprovalInferred: true;
  noCyberScoreV1Updates: true;
  digest: string;
};
export type PassiveScheduleExport = {
  schema: "cyberpilot.exposure.passive.schedule.export.v1";
  format: "JSON" | "CSV" | "MARKDOWN";
  filename: string;
  mimeType: string;
  output: string;
  sha256: string;
  sourceDigest: string;
  certificationsIssued: 0;
  liveCallsPerformed: 0;
};
const sha = (value: unknown) =>
  sha256V2(canonicalV2(value));
function safeText(s: string) {
  return s.replace(/[\u0000-\u001f\u007f]/g, " ");
}
function csv(x: string | number | null) {
  const text = safeText(String(x ?? ""));
  const neutralized = /^[=+@-]/.test(text) ? "'" + text : text;
  return '"' + neutralized.replaceAll('"', '""') + '"';
}
export function buildPassiveScheduleSummary(
  organizationId: string,
  schedules: readonly PassiveScheduleView[],
  evaluatedAt: string,
): PassiveScheduleSummary {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(organizationId) ||
      !Number.isFinite(Date.parse(evaluatedAt)) ||
      schedules.length > 500 ||
      schedules.some(x => x.organizationId !== organizationId ||
        x.legalConsentVerified || x.activeNetworkConnections !== 0 ||
        !/^[a-f0-9]{64}$/.test(x.policyDigest)) ||
      new Set(schedules.map(x => x.domain)).size !== schedules.length)
    throw Error("Cross-tenant or unsupported source for schedule summary.");
  const rows = [...schedules].sort((a, b) =>
    a.domain.localeCompare(b.domain));
  const canonical = {
    schema: "cyberpilot.exposure.passive.schedule.report.v1" as const,
    organizationId, evaluatedAt, count: rows.length,
    policyDigests: rows.map(x => x.policyDigest),
    byState: Object.fromEntries([
      "DISABLED","PAUSED","READY","REVOKED",
    ].map(x => [x, rows.filter(y => y.state === x).length])),
    bySource: Object.fromEntries([
      "DNS","TLS_HANDSHAKE","HTTPS_HEADERS",
    ].map(x => [x, rows.filter(y =>
      y.sources.includes(x as "DNS")).length])),
    enabledForNetwork: 0 as const,
    verifiedLegalConsent: 0 as const,
    pausedOrDisabled: rows.filter(x =>
      x.state === "PAUSED" || x.state === "DISABLED").length,
    revoked: rows.filter(x => x.state === "REVOKED").length,
    configuredDnsQuota: rows.reduce((n,x) =>
      n + x.dailyDnsLimit, 0),
    configuredTlsQuota: rows.reduce((n,x) =>
      n + x.dailyTlsLimit, 0),
    configuredHttpQuota: rows.reduce((n,x) =>
      n + x.dailyHttpLimit, 0),
    unansweredAuthorizationQuestions: [
      "Which authorized customer has attested legal scope?",
      "Who independently verified the customer consent record?",
      "Which trusted collector will enforce the pinned IP policy?",
      "Which shared quota admission service will issue network leases?",
    ],
    domainRows: rows.map(x => ({
      domain: x.domain, revision: x.revision, state: x.state,
      sources: x.sources, nextEligibleAt: x.nextEligibleAt,
      policyDigest: x.policyDigest,
      mayScanAutomatically: false as const,
      independentlyVerifiedLegalConsent: false as const,
      technicalRiskScore: null,
    })),
    limitations: [
      "Planning is not a live passive scan.",
      "No legal authorization is inferred from domain TXT proof.",
      "Network budget is a proposal until trusted consent is established.",
      "No certificate or approved remediation is issued.",
    ],
    noNetworkRequests: true as const,
    noLegalApprovalInferred: true as const,
    noCyberScoreV1Updates: true as const,
  };
  return { ...canonical, digest: sha(canonical) };
}
export function verifyPassiveScheduleSummary(
  report: PassiveScheduleSummary,
) {
  const { digest, ...canonical } = report;
  const errors: string[] = [];
  if (sha(canonical) !== digest)
    errors.push("REPORT_DIGEST_MISMATCH");
  if (report.enabledForNetwork !== 0 ||
      report.verifiedLegalConsent !== 0 ||
      !report.noNetworkRequests || !report.noLegalApprovalInferred ||
      !report.noCyberScoreV1Updates)
    errors.push("FALSE_LIVE_APPROVAL");
  if (report.count !== report.domainRows.length)
    errors.push("SOURCE_COUNT_INCONSISTENT");
  if (report.domainRows.some(x =>
    x.mayScanAutomatically ||
    x.independentlyVerifiedLegalConsent ||
    x.technicalRiskScore !== null))
    errors.push("FALSE_DOMAIN_SECURITY_SCORE");
  return { valid: errors.length === 0, errors };
}
export function exportPassiveScheduleSummary(
  report: PassiveScheduleSummary,
  format: PassiveScheduleExport["format"],
): PassiveScheduleExport {
  if (!verifyPassiveScheduleSummary(report).valid ||
      !["JSON","CSV","MARKDOWN"].includes(format))
    throw Error("Cannot export invalid policy report.");
  const output = format === "JSON" ?
    JSON.stringify(report, null, 2) + "\n" :
    format === "CSV" ? [
      ["domain","state","revision","sources","consentVerified"]
        .map(csv).join(","),
      ...report.domainRows.map(x => [
        x.domain, x.state, x.revision,
        x.sources.join("|"), "false",
      ].map(csv).join(",")),
    ].join("\r\n") + "\r\n" :
    [
      "# Exposure passive schedule — safety report",
      "Organization: " + report.organizationId,
      "As of: " + report.evaluatedAt,
      "Network collection: DISABLED",
      "Legal consent verified: NO",
      "Schedules: " + report.count, "",
      ...report.domainRows.map(x =>
        "- " + safeText(x.domain) + " · " + x.state +
          " · " + x.sources.join(", ")),
      "", "## Outstanding prerequisites",
      ...report.unansweredAuthorizationQuestions.map(x => "- " + x),
    ].join("\n") + "\n";
  return {
    schema: "cyberpilot.exposure.passive.schedule.export.v1",
    format,
    filename: "exposure-passive-" + report.evaluatedAt.slice(0, 10) +
      (format === "JSON" ? ".json" :
        format === "CSV" ? ".csv" : ".md"),
    mimeType: format === "JSON" ? "application/json" :
      format === "CSV" ? "text/csv" : "text/markdown",
    output, sha256: sha256V2(output),
    sourceDigest: report.digest,
    certificationsIssued: 0, liveCallsPerformed: 0,
  };
}
