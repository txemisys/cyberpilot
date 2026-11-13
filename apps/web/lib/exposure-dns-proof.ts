import { Resolver } from "node:dns/promises";
import { createHash, timingSafeEqual } from "node:crypto";
import {
  normalizeExposureDomain, sha256V2,
} from "@cyberpilot/risk-engine";

/**
 * Explicit DNS TXT ownership challenge lookup.
 * No arbitrary URL fetching, no port or subdomain scan, no guessing selectors.
 */
export type ExposureProofResolver = {
  resolveTxt(host: string): Promise<string[][]>;
  cancel?(): void;
};
export type ExposureDnsProofInput = {
  organizationId: string;
  domain: string;
  method: "DNS_TOKEN";
  token: string;
  challengeDigest: string;
  expiresAt: string;
  checkedAt: string;
};
export type ExposureDnsProofResult = {
  schema: "cyberpilot.exposure.dns.proof.result.v1";
  organizationId: string;
  domain: string;
  checkedAt: string;
  queriedName: string;
  queryCount: 1;
  bytesRead: number;
  recordsRead: number;
  responseDigest: string | null;
  state: "MATCH" | "MISSING" | "AMBIGUOUS" |
    "TIMEOUT" | "DNS_ERROR" | "EXPIRED" |
    "INVALID_CHALLENGE" | "OVERSIZED";
  challengeMatched: boolean;
  dnsTxtObserved: boolean;
  networkQueriesPerformed: number;
  activePortScanningPerformed: 0;
  httpRequestsPerformed: 0;
  dataWasNotAltered: true;
  externalCustomerConsentAttested: false;
  resolvedIpValidated: false;
  customerSecurityCertified: false;
};
export type ExposureDnsProofPolicy = {
  timeoutMs: number;
  maxTxtRecords: number;
  maxTxtBytes: number;
  maxDomainCharacters: number;
  requireExactToken: true;
  allowRedirects: false;
  allowUnrelatedDomains: false;
};
export const DEFAULT_DNS_PROOF_POLICY: ExposureDnsProofPolicy = {
  timeoutMs: 4000,
  maxTxtRecords: 20,
  maxTxtBytes: 8192,
  maxDomainCharacters: 253,
  requireExactToken: true,
  allowRedirects: false,
  allowUnrelatedDomains: false,
};
function hex64(value: string) {
  return /^[a-f0-9]{64}$/.test(value);
}
function validTime(s: string) {
  return Number.isFinite(Date.parse(s)) &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(s) &&
    new Date(s).toISOString() === s;
}
function domainDigest(
  organizationId: string, domain: string,
  method: "DNS_TOKEN", token: string,
) {
  return sha256V2(organizationId + "\u0000" + domain +
    "\u0000" + method + "\u0000" + token);
}
function exactDigest(a: string, b: string) {
  if (!hex64(a) || !hex64(b)) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function report(
  input: ExposureDnsProofInput,
  state: ExposureDnsProofResult["state"],
  extra: {
    bytesRead?: number;
    recordsRead?: number;
    responseDigest?: string | null;
    queried?: number;
  } = {},
): ExposureDnsProofResult {
  return {
    schema: "cyberpilot.exposure.dns.proof.result.v1",
    organizationId: input.organizationId,
    domain: input.domain,
    checkedAt: input.checkedAt,
    queriedName: "_cyberpilot-verification." + input.domain,
    queryCount: 1,
    bytesRead: extra.bytesRead ?? 0,
    recordsRead: extra.recordsRead ?? 0,
    responseDigest: extra.responseDigest ?? null,
    state, challengeMatched: state === "MATCH",
    dnsTxtObserved: [
      "MATCH", "MISSING", "AMBIGUOUS", "OVERSIZED",
    ].includes(state),
    networkQueriesPerformed: extra.queried ?? 0,
    activePortScanningPerformed: 0,
    httpRequestsPerformed: 0,
    dataWasNotAltered: true,
    externalCustomerConsentAttested: false,
    resolvedIpValidated: false,
    customerSecurityCertified: false,
  };
}
function verifyPolicy(policy: ExposureDnsProofPolicy) {
  if (!Number.isSafeInteger(policy.timeoutMs) ||
      policy.timeoutMs < 250 || policy.timeoutMs > 5000 ||
      !Number.isSafeInteger(policy.maxTxtRecords) ||
      policy.maxTxtRecords < 1 || policy.maxTxtRecords > 50 ||
      !Number.isSafeInteger(policy.maxTxtBytes) ||
      policy.maxTxtBytes < 64 || policy.maxTxtBytes > 16384 ||
      policy.maxDomainCharacters !== 253 ||
      !policy.requireExactToken ||
      policy.allowRedirects || policy.allowUnrelatedDomains)
    throw Error("Invalid DNS proof policy.");
}
function validateInput(input: ExposureDnsProofInput) {
  let validDomain = false;
  try {
    validDomain = normalizeExposureDomain(input.domain) === input.domain;
  } catch { validDomain = false; }
  return validDomain &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(input.organizationId) &&
    input.method === "DNS_TOKEN" &&
    hex64(input.token) && hex64(input.challengeDigest) &&
    validTime(input.expiresAt) && validTime(input.checkedAt);
}
export async function verifyExposureDnsProof(
  input: ExposureDnsProofInput,
  resolver: ExposureProofResolver = new Resolver(),
  policy: ExposureDnsProofPolicy = DEFAULT_DNS_PROOF_POLICY,
): Promise<ExposureDnsProofResult> {
  verifyPolicy(policy);
  if (!validateInput(input))
    return report(input, "INVALID_CHALLENGE");
  if (input.checkedAt > input.expiresAt)
    return report(input, "EXPIRED");
  const digest = domainDigest(
    input.organizationId, input.domain, input.method,
    input.token);
  if (!exactDigest(digest, input.challengeDigest))
    return report(input, "INVALID_CHALLENGE");
  const target = "_cyberpilot-verification." + input.domain;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let timedOut = false;
  try {
    const txt = await Promise.race([
      resolver.resolveTxt(target),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          resolver.cancel?.();
          reject(Error("DNS_PROOF_TIMEOUT"));
        }, policy.timeoutMs);
      }),
    ]);
    const bytesRead = txt.reduce((n, row) =>
      n + row.reduce((m, segment) =>
        m + Buffer.byteLength(segment, "utf8"), 0), 0);
    if (txt.length > policy.maxTxtRecords ||
        bytesRead > policy.maxTxtBytes)
      return report(input, "OVERSIZED", {
        bytesRead, recordsRead: txt.length,
        responseDigest: createHash("sha256")
          .update(String(txt.length) + ":" + bytesRead)
          .digest("hex"),
        queried: 1,
      });
    const records = txt.map(parts => parts.join(""));
    const expected = "cyberpilot-domain-verification=" + input.token;
    const exactMatches = records.filter(record => record === expected);
    // More than one exact proof record is ambiguous even if both match.
    const state = exactMatches.length > 1 ? "AMBIGUOUS" :
      exactMatches.length === 1 ? "MATCH" : "MISSING";
    // SHA-256 binds the actual observed strings, never persist the
    // plaintext TXT because it contains the short-lived challenge.
    return report(input, state, {
      bytesRead, recordsRead: records.length,
      responseDigest: sha256V2(
        JSON.stringify([...records].sort())),
      queried: 1,
    });
  } catch {
    return report(input, timedOut ? "TIMEOUT" : "DNS_ERROR", {
      queried: 1,
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}
export function classifyExposureProofForPersisting(
  proof: ExposureDnsProofResult,
) {
  if (proof.networkQueriesPerformed > 1 ||
      proof.httpRequestsPerformed !== 0 ||
      proof.activePortScanningPerformed !== 0 ||
      proof.externalCustomerConsentAttested ||
      proof.customerSecurityCertified)
    throw Error("DNS proof exceeded passive authorization boundary.");
  return {
    organizationId: proof.organizationId,
    domain: proof.domain,
    status: proof.state === "MATCH" ?
      "VERIFIED" as const : proof.state === "EXPIRED" ?
        "EXPIRED" as const : "PENDING" as const,
    checkedAt: proof.checkedAt,
    evidenceDigest: proof.responseDigest,
    externalConsentProven: false as const,
    authorizedPortScanning: false as const,
    auditReason: proof.state,
  };
}
export function summarizeExposureDnsProof(
  result: ExposureDnsProofResult,
) {
  return {
    domain: result.domain,
    state: result.state,
    independentTxtAnswerObserved: result.dnsTxtObserved,
    challengeMatched: result.challengeMatched,
    boundedDnsQueries: result.networkQueriesPerformed,
    activeScanCount: 0 as const,
    externalLegalApprovalProven: false as const,
    verifiedOrganizationWideSecurity: false as const,
    explanation: result.state === "MATCH" ?
      "DNS challenge token observed at the explicit authorized name." :
      result.state === "TIMEOUT" ?
        "Resolver timeout leaves ownership unverified." :
        "The challenge has not been independently confirmed.",
  };
}
