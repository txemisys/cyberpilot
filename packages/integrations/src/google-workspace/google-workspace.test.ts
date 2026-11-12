import { describe, expect, it } from "vitest";
import {
  CAPABILITIES, normalizeUser, normalizeDomain,
  normalizeBatch, verifyObservation, buildEvidenceRecords,
  summarizeCoverage, extractReportEvents, subjectHash,
} from "./directory-contract";
import {
  parseGoogleTransportPolicy, buildGoogleResourceUrl,
  safeRetryAfter, deterministicBackoff, createFixtureFetch,
  collectGoogleWorkspace, inspectGoogleEnvironment,
} from "./transport";

const org = "org-12345", time = "2026-11-12T10:00:00.000Z";
const policy = parseGoogleTransportPolicy({
  maxRetriesPerPage: 0, maxPagesPerResource: 2, includeReports: false,
});
const user = {
  id: "10001", primaryEmail: "sample@example.com",
  isAdmin: true, isEnrolledIn2Sv: false,
  isEnforcedIn2Sv: false, suspended: false,
  lastLoginTime: "2026-11-11T10:00:00Z",
};
function fixture() {
  const urls = ["USERS", "DOMAINS", "ORG_UNITS"].map(resource =>
    buildGoogleResourceUrl(resource as "USERS" | "DOMAINS" |
      "ORG_UNITS", "my_customer", policy));
  return Object.fromEntries(urls.map((url, i) =>
    [url.pathname + "?", [{
      ...(i === 0 ? { users: [user] } : {}),
      ...(i === 1 ? { domains: [{ domainName: "example.com",
        verified: true }] } : {}),
      ...(i === 2 ? { organizationUnits: [{
        orgUnitId: "ou1", name: "Test", orgUnitPath: "/Test",
      }] } : {}),
    }]]));
}
describe("Google Workspace offline safe contracts", () => {
  it("defines six capabilities but does not assume provider coverage", () => {
    expect(CAPABILITIES).toHaveLength(6);
    const observation = normalizeBatch({
      organizationId: org, checkedAt: time,
      source: "SYNTHETIC_FIXTURE", users: [user],
    });
    expect(observation.unknownCapabilities).toHaveLength(6);
    expect(observation.liveProviderVerified).toBe(false);
    expect(verifyObservation(observation).valid).toBe(true);
  });
  it("normalizes identity without passwords, tokens or hidden fields", () => {
    const result = normalizeUser({
      ...user, customSchemas: { secret: "bad" },
      password: "sensitive", aliases: ["alias@example.com"],
    });
    expect(result.isEnrolledIn2Sv).toBe(false);
    expect(result.unsupportedFields).toContain("password");
    expect(JSON.stringify(result)).not.toContain("sensitive");
  });
  it("does not turn missing or unavailable MFA into observed healthy", () => {
    const observation = normalizeBatch({
      organizationId: org, checkedAt: time,
      source: "SYNTHETIC_FIXTURE", users: [{ ...user,
        isEnrolledIn2Sv: undefined }],
      coverage: { DIRECTORY_USERS: "AVAILABLE",
        USER_MFA_ATTRIBUTES: "REQUIRES_PERMISSION" },
    });
    const evidence = buildEvidenceRecords(observation);
    expect(evidence.find(x => x.controlId === "GOOGLE_USER_2SV")
      ?.state).toBe("UNKNOWN");
    expect(evidence.every(x => !x.externalLiveVerified)).toBe(true);
  });
  it("does not invent availability on a partial provider report", () => {
    const observation = normalizeBatch({
      organizationId: org, checkedAt: time,
      source: "SYNTHETIC_FIXTURE",
      coverage: { DIRECTORY_USERS: "AVAILABLE" },
      truncation: { DIRECTORY_USERS: true },
    });
    expect(summarizeCoverage(observation).partial).toBe(true);
    expect(summarizeCoverage(observation).tenantSecurityProven).toBe(false);
  });
  it("rejects repeated identity IDs and malformed domain data", () => {
    expect(() => normalizeBatch({
      organizationId: org, checkedAt: time,
      source: "SYNTHETIC_FIXTURE", users: [user, user],
    })).toThrow();
    expect(() => normalizeDomain({ domainName: "bad..domain" }))
      .toThrow();
  });
  it("hashes report actors with organization separation", () => {
    expect(subjectHash("org-one", "a@example.com"))
      .not.toBe(subjectHash("org-two", "a@example.com"));
    const reports = extractReportEvents({
      id: { time: "2026-11-12T10:00:00Z",
        uniqueQualifier: "11" },
      actor: { email: "admin@example.com", ipAddress: "127.0.0.1" },
      events: [{ name: "login_success",
        parameters: [{ name: "token", value: "secret" },
          { name: "success", boolValue: true }] }],
    }, org, "LOGIN");
    expect(reports).toHaveLength(1);
    expect(reports[0].parameters).toEqual([
      { name: "success", value: "true" },
    ]);
    expect(JSON.stringify(reports)).not.toContain("admin@example.com");
    expect(JSON.stringify(reports)).not.toContain("127.0.0.1");
  });
  it("bounds page sizes, retries and total request budgets", () => {
    expect(() => parseGoogleTransportPolicy({ pageSize: 501 })).toThrow();
    expect(() => parseGoogleTransportPolicy({ maxTotalRequests: 201 }))
      .toThrow();
    expect(() => parseGoogleTransportPolicy({ unknown: 1 })).toThrow();
    expect(() => parseGoogleTransportPolicy({
      timeoutMs: 2000, maxElapsedMs: 1000,
    })).toThrow();
  });
  it("only allows Google Admin SDK origin and known resource paths", () => {
    const url = buildGoogleResourceUrl("USERS", "my_customer", policy);
    expect(url.origin).toBe("https://admin.googleapis.com");
    expect(url.searchParams.get("customer")).toBe("my_customer");
    expect(() => buildGoogleResourceUrl("USERS",
      "../somewhere", policy)).toThrow();
  });
  it("respects safe Retry-After and bounded backoff", () => {
    expect(safeRetryAfter("2", 5000)).toBe(2000);
    expect(safeRetryAfter("invalid", 5000)).toBe(null);
    expect(deterministicBackoff(5, policy, null))
      .toBeLessThanOrEqual(policy.maxBackoffMs);
  });
  it("refuses any real provider without explicit deferred consent", () => {
    expect(() => inspectGoogleEnvironment({
      organizationId: org, customerId: "my_customer", token: "testing",
      checkedAt: time, source: "GOOGLE_DIRECTORY",
      consentVerifiedByCaller: true, liveProviderAllowedByCaller: false,
    })).toThrow();
  });
  it("collects solely mocked pages with no account writes or LIVE claims", async () => {
    const result = await collectGoogleWorkspace({
      environment: {
        organizationId: org, customerId: "my_customer",
        token: "fixture-token", checkedAt: time,
        source: "SYNTHETIC_FIXTURE",
        consentVerifiedByCaller: true,
        liveProviderAllowedByCaller: false,
      },
      policy: { ...policy, includeReports: false },
      fetcher: createFixtureFetch(fixture()),
    });
    expect(result.observation.users).toHaveLength(1);
    expect(result.observation.domains).toHaveLength(1);
    expect(result.observation.orgUnits).toHaveLength(1);
    expect(result.providerContacted).toBe(false);
    expect(result.accountWrites).toBe(0);
    expect(result.externalLiveVerified).toBe(false);
    expect(JSON.stringify(result)).not.toContain("fixture-token");
  });
  it("reports partial evidence on denied API permissions", async () => {
    const result = await collectGoogleWorkspace({
      environment: {
        organizationId: org, customerId: "my_customer",
        token: "fixture-token", checkedAt: time,
        source: "SYNTHETIC_FIXTURE",
        consentVerifiedByCaller: true,
        liveProviderAllowedByCaller: false,
      },
      policy,
      fetcher: async () => ({
        status: 403, ok: false,
        headers: { get: () => null }, text: async () => "{}",
      }),
    });
    expect(result.evidenceIncomplete).toBe(true);
    expect(result.failures.some(x => x.category === "PERMISSION"))
      .toBe(true);
    expect(result.observation.coverage.DIRECTORY_USERS)
      .toBe("REQUIRES_PERMISSION");
  });
});
