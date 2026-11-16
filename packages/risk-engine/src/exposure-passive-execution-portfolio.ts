import { canonicalV2 } from "./multisource-v2-contract";
import { sha256V2 } from "./multisource-v2-history";
import {
  executePassiveCollection,
  type PassiveExecutionLease,
  type PassiveExecutionOptions,
  type PassiveExecutionResult,
} from "./exposure-passive-execution-guard";
import {
  reconcilePassiveExecution,
  verifyPassiveExecutionEvidence,
  type PassiveExecutionEvidence,
} from "./exposure-passive-execution-verification";
import { type PassiveCollectorRequest } from
  "./exposure-passive-collection-policy";

/**
 * Calls only injected executor capabilities, then immediately runs a
 * second, independent reconciliation. No network client is created.
 */
export type VerifiedPassiveExecution = {
  schema: "cyberpilot.exposure.execution.verified.v1";
  result: PassiveExecutionResult;
  evidence: PassiveExecutionEvidence;
  reportIntegrityVerified: boolean;
  noOutboundWithoutLease: true;
  noCustomerCertification: true;
};
export async function executeAndVerifyPassiveCollection(
  request: PassiveCollectorRequest,
  lease: PassiveExecutionLease | null,
  options: PassiveExecutionOptions,
): Promise<VerifiedPassiveExecution> {
  const result = await executePassiveCollection(request, lease, options);
  const evidence = reconcilePassiveExecution(
    request, lease, result, options.now(),
  );
  const verification = verifyPassiveExecutionEvidence(
    evidence, request.organizationId,
  );
  return {
    schema: "cyberpilot.exposure.execution.verified.v1",
    result, evidence,
    reportIntegrityVerified: verification.valid,
    noOutboundWithoutLease: true,
    noCustomerCertification: true,
  };
}
export type PassiveExecutionPortfolio = {
  schema: "cyberpilot.exposure.execution.portfolio.v1";
  organizationId: string;
  generatedAt: string;
  samples: number;
  domains: string[];
  requestIds: string[];
  totals: {
    traceable: number;
    denied: number;
    partial: number;
    invalid: number;
    dnsCalls: number;
    tlsCalls: number;
    headCalls: number;
    totalCalls: number;
    missingSources: number;
    blockedGates: number;
    advisoryGates: number;
  };
  perDomain: Array<{
    domain: string;
    samples: number;
    lastEvaluatedAt: string;
    lastVerdict: PassiveExecutionEvidence["verdict"];
    networkCalls: number;
    unknownSources: number;
    blockedGates: string[];
    observedSecurityPosture: "NOT_DETERMINED";
    liveConsentAuthorizedByPortfolio: false;
  }>;
  anomalies: Array<{
    code: string;
    domain: string | null;
    requestId: string | null;
    evidenceDigest: string | null;
  }>;
  limitations: string[];
  digest: string;
  legalApprovalInferred: false;
  securityScoreProduced: false;
  externallyCertified: false;
};
function dateValid(s: string): boolean {
  return typeof s === "string" &&
    Number.isFinite(Date.parse(s)) &&
    new Date(s).toISOString() === s;
}
function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}
function sum(values: PassiveExecutionEvidence[],
  key: (e: PassiveExecutionEvidence) => number) {
  return values.reduce((result, value) => result + key(value), 0);
}
function fingerprint(value: unknown): string {
  return sha256V2(canonicalV2(value));
}
function statusRank(value: PassiveExecutionEvidence["verdict"]) {
  return value === "INVALID" ? 3 :
    value === "DENIED" ? 2 :
    value === "PARTIAL" ? 1 : 0;
}
export function buildPassiveExecutionPortfolio(
  organizationId: string,
  items: readonly PassiveExecutionEvidence[],
  generatedAt: string,
): PassiveExecutionPortfolio {
  if (!dateValid(generatedAt) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(organizationId) ||
      items.length > 1000)
    throw Error("Invalid passive portfolio bounds or tenant.");
  const anomalies: PassiveExecutionPortfolio["anomalies"] = [];
  const valid: PassiveExecutionEvidence[] = [];
  const requests = new Set<string>();
  for (const item of items) {
    const check = verifyPassiveExecutionEvidence(
      item, organizationId,
    );
    if (!check.valid) {
      anomalies.push({
        code: check.errors.join(","),
        domain: item.domain ?? null,
        requestId: item.requestId ?? null,
        evidenceDigest: item.integrityDigest ?? null,
      });
      continue;
    }
    if (requests.has(item.requestId)) {
      anomalies.push({
        code: "DUPLICATE_REQUEST_ID",
        domain: item.domain,
        requestId: item.requestId,
        evidenceDigest: item.integrityDigest,
      });
      continue;
    }
    requests.add(item.requestId);
    valid.push(item);
  }
  const domains = sortedUnique(valid.map(x => x.domain));
  const perDomain = domains.map(domain => {
    const reports = valid.filter(x => x.domain === domain)
      .sort((a, b) => b.evaluatedAt.localeCompare(a.evaluatedAt));
    const latest = reports[0]!;
    const blockedGates = sortedUnique(reports.flatMap(x => x.blockers));
    return {
      domain,
      samples: reports.length,
      lastEvaluatedAt: latest.evaluatedAt,
      lastVerdict: latest.verdict,
      networkCalls: sum(reports, x => x.consumedCalls.total),
      unknownSources: sum(reports, x =>
        x.sourceSummary.unknown.length +
        x.sourceSummary.missing.length),
      blockedGates,
      observedSecurityPosture: "NOT_DETERMINED" as const,
      liveConsentAuthorizedByPortfolio: false as const,
    };
  });
  const canonical = {
    schema: "cyberpilot.exposure.execution.portfolio.v1" as const,
    organizationId, generatedAt,
    samples: valid.length,
    domains, requestIds: [...requests].sort(),
    totals: {
      traceable: valid.filter(x => x.verdict === "TRACEABLE").length,
      denied: valid.filter(x => x.verdict === "DENIED").length,
      partial: valid.filter(x => x.verdict === "PARTIAL").length,
      invalid: valid.filter(x => x.verdict === "INVALID").length,
      dnsCalls: sum(valid, x => x.consumedCalls.DNS),
      tlsCalls: sum(valid, x => x.consumedCalls.TLS_HANDSHAKE),
      headCalls: sum(valid, x => x.consumedCalls.HTTPS_HEADERS),
      totalCalls: sum(valid, x => x.consumedCalls.total),
      missingSources: sum(valid, x => x.sourceSummary.missing.length),
      blockedGates: sum(valid, x => x.blockers.length),
      advisoryGates: sum(valid, x => x.advisory.length),
    },
    perDomain, anomalies,
    limitations: [
      "Aggregated execution metadata is not an asset inventory.",
      "No domain proof or collection receipt grants legal consent.",
      "Run-level SHA-256 is not proof of authentic external origin.",
      "Blocked and unknown samples cannot be interpreted as safe.",
      "Technical posture remains NOT_DETERMINED for every domain.",
      "This portfolio never enables a live worker or updates CyberScore.",
    ],
    legalApprovalInferred: false as const,
    securityScoreProduced: false as const,
    externallyCertified: false as const,
  };
  return { ...canonical, digest: fingerprint(canonical) };
}
export function verifyPassiveExecutionPortfolio(
  portfolio: PassiveExecutionPortfolio,
  expectedTenant?: string,
) {
  const { digest, ...canonical } = portfolio;
  const errors: string[] = [];
  if (fingerprint(canonical) !== digest)
    errors.push("PORTFOLIO_TAMPERED");
  if (expectedTenant && portfolio.organizationId !== expectedTenant)
    errors.push("PORTFOLIO_CROSS_TENANT");
  if (portfolio.legalApprovalInferred !== false ||
      portfolio.securityScoreProduced !== false ||
      portfolio.externallyCertified !== false)
    errors.push("PORTFOLIO_FALSE_CERTIFICATION");
  if (portfolio.perDomain.some(x =>
    x.observedSecurityPosture !== "NOT_DETERMINED" ||
    x.liveConsentAuthorizedByPortfolio !== false))
    errors.push("DOMAIN_FALSE_LIVE_AUTHORIZATION");
  if (portfolio.domains.length !==
      new Set(portfolio.domains).size ||
      portfolio.requestIds.length !==
      new Set(portfolio.requestIds).size)
    errors.push("DUPLICATE_PORTFOLIO_SOURCE");
  if (portfolio.totals.traceable +
      portfolio.totals.denied +
      portfolio.totals.partial +
      portfolio.totals.invalid !== portfolio.samples)
    errors.push("PORTFOLIO_SAMPLE_COUNT_INVALID");
  return { valid: errors.length === 0, errors };
}
export function comparePassiveExecutionPortfolios(
  before: PassiveExecutionPortfolio,
  after: PassiveExecutionPortfolio,
) {
  if (!verifyPassiveExecutionPortfolio(before).valid ||
      !verifyPassiveExecutionPortfolio(after).valid ||
      before.organizationId !== after.organizationId ||
      before.generatedAt >= after.generatedAt)
    throw Error("Cross-tenant or stale passive portfolio.");
  const older = new Set(before.requestIds);
  const newer = new Set(after.requestIds);
  const olderDomains = new Set(before.domains);
  const newerDomains = new Set(after.domains);
  const newSamples = after.requestIds.filter(x => !older.has(x));
  const removedSamples = before.requestIds.filter(x => !newer.has(x));
  const newDomains = after.domains.filter(x => !olderDomains.has(x));
  const vanishedDomains = before.domains.filter(x => !newerDomains.has(x));
  const oldWorst = Math.max(0,
    ...before.perDomain.map(x => statusRank(x.lastVerdict)));
  const newWorst = Math.max(0,
    ...after.perDomain.map(x => statusRank(x.lastVerdict)));
  return {
    organizationId: after.organizationId,
    fromDigest: before.digest,
    toDigest: after.digest,
    newSamples, removedSamples, newDomains, vanishedDomains,
    totalCallDelta: after.totals.totalCalls - before.totals.totalCalls,
    sourceCountDelta: after.samples - before.samples,
    worstTechnicalExecutionStateChanged: oldWorst !== newWorst,
    legalConsentStillRequired: true as const,
    improvedSecurityPostureInferred: false as const,
    automaticRiskScoreUpdate: false as const,
  };
}
