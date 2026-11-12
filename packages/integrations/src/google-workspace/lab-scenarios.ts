import { createHash } from "node:crypto";
import { canonicalGoogleHash } from "./canonical-json";
import {
  CAPABILITIES, type GoogleCapability,
  type GoogleDirectoryObservation,
} from "./directory-contract";
import {
  buildGoogleResourceUrl, parseGoogleTransportPolicy,
  validateGoogleUrl, type GoogleApiResource, type GoogleFetcher,
  type GoogleTransportPolicy,
} from "./transport";

/** Deterministic, tenant-isolated Google Admin SDK mock; never uses network. */
export type GoogleLabScenarioName =
  "HEALTHY_REFERENCE" | "MFA_GAPS" | "ADMIN_RISK" |
  "PAGINATED_DIRECTORY" | "PERMISSION_DENIED" |
  "QUOTA_THEN_RECOVER" | "QUOTA_EXHAUSTED" |
  "PARTIAL_DIRECTORY" | "REPORTS_UNAVAILABLE" |
  "REPORTS_PARTIAL" | "UNKNOWN_MFA" |
  "SUSPENDED_ADMIN" | "NO_IDENTITIES" |
  "MALFORMED_PAGE" | "REPEATED_PAGE" |
  "TRANSPORT_TIMEOUT" | "DOMAIN_UNVERIFIED";
export type GoogleLabScenario = {
  id: GoogleLabScenarioName;
  title: string;
  purpose: string;
  expectedRisk: "NONE_OBSERVED" | "POTENTIAL" | "UNKNOWN";
  expectedCoverage: "LOCAL_COMPLETE" | "PARTIAL" | "DENIED";
  requiredResources: GoogleApiResource[];
  producesGoogleTraffic: false;
  customerTenantAuthenticated: false;
  containsRealUserData: false;
  gates: string[];
};
export type GoogleMockIdentity = {
  id: string;
  primaryEmail: string;
  isAdmin: boolean | null;
  isDelegatedAdmin: boolean | null;
  isEnrolledIn2Sv: boolean | null;
  isEnforcedIn2Sv: boolean | null;
  suspended: boolean | null;
  lastLoginTime: string | null;
  creationTime: string;
  orgUnitPath: string;
  aliases: string[];
};
export type GoogleMockDomain = {
  domainName: string;
  isPrimary: boolean;
  verified: boolean | null;
};
export type GoogleMockOrgUnit = {
  orgUnitId: string;
  orgUnitPath: string;
  parentOrgUnitPath: string | null;
  name: string;
  blockInheritance: boolean;
};
export type GoogleMockEvent = {
  id: {
    time: string;
    uniqueQualifier: string;
    applicationName: string;
  };
  actor: { email: string };
  events: Array<{
    name: string;
    parameters: Array<{
      name: string;
      value?: string;
      boolValue?: boolean;
      intValue?: number;
    }>;
  }>;
};
export type GoogleLabScenarioSource = {
  schema: "cyberpilot.google.lab.scenario.v1";
  id: GoogleLabScenarioName;
  organizationId: string;
  checkedAt: string;
  users: GoogleMockIdentity[];
  domains: GoogleMockDomain[];
  orgUnits: GoogleMockOrgUnit[];
  loginEvents: GoogleMockEvent[];
  adminEvents: GoogleMockEvent[];
  expectedPartial: boolean;
  expectedPermissionFailure: boolean;
  expectedQuotaFailure: boolean;
  description: string;
  sourceDigest: string;
  requiresRealProvider: false;
  containsCustomerEmails: false;
  userIdsGeneratedLocally: true;
};
export type GoogleLabFault = {
  resource: GoogleApiResource;
  page: number;
  kind: "HTTP_403" | "HTTP_429" | "HTTP_503" |
    "BAD_JSON" | "PAGE_CYCLE" | "TIMEOUT" |
    "HTTP_429_ONCE" | "NO_ITEMS";
  maxActivations: number;
  status: number;
  affectsRealGoogle: false;
};
export type GoogleLabMockTrace = {
  schema: "cyberpilot.google.mock.trace.v1";
  scenario: GoogleLabScenarioName;
  organizationId: string;
  requestedAt: string;
  resource: GoogleApiResource;
  page: number;
  status: number;
  attempt: number;
  responseDigest: string;
  returningNextPage: boolean;
  durationVirtualMs: number;
  usedFixtureOnly: true;
  bearerTokenLogged: false;
  rawAuthorizationHeadersLogged: false;
};
export type GoogleLabSimulation = {
  scenario: GoogleLabScenarioSource;
  fetcher: GoogleFetcher;
  transcript: GoogleLabMockTrace[];
  counts: Record<GoogleApiResource, number>;
  faults: GoogleLabFault[];
  reset(): void;
  inspect(): {
    scenario: GoogleLabScenarioName;
    requests: number;
    failures: number;
    pages: number;
    maxRequestsPerResource: number;
    liveRequests: 0;
    credentialLeaks: 0;
    transcriptDigest: string;
  };
};
const resources = [
  "USERS", "DOMAINS", "ORG_UNITS", "LOGIN_AUDIT", "ADMIN_AUDIT",
] as const;
export const GOOGLE_LAB_SCENARIOS: readonly GoogleLabScenario[] = [
  {
    id: "HEALTHY_REFERENCE", title: "Observed fixture baseline",
    purpose: "Known fixture with enrolled identities, verified domain and both activity streams",
    expectedRisk: "NONE_OBSERVED", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: [...resources], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["fixture", "all-capabilities", "no-live-claims"],
  },
  {
    id: "MFA_GAPS", title: "Users without two-step verification",
    purpose: "Report observed enrollment and enforcement gaps without executing remedies",
    expectedRisk: "POTENTIAL", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["2sv-unknown-safety", "risk-only", "no-account-writes"],
  },
  {
    id: "ADMIN_RISK", title: "Superadministrator protection gaps",
    purpose: "Privilege-sensitive assessment with MFA false and old login",
    expectedRisk: "POTENTIAL", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["superadmin", "mfa", "inactivity"],
  },
  {
    id: "PAGINATED_DIRECTORY", title: "Multiple user pages",
    purpose: "Collect deterministic users over bounded, explicit page tokens",
    expectedRisk: "NONE_OBSERVED", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["page-token", "no-duplicates", "max-pages"],
  },
  {
    id: "PERMISSION_DENIED", title: "Directory permission denied",
    purpose: "Return 403 without assuming IAM coverage or accepting invented permission",
    expectedRisk: "UNKNOWN", expectedCoverage: "DENIED",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["http-403", "unknown", "no-false-score"],
  },
  {
    id: "QUOTA_THEN_RECOVER", title: "429 followed by recovery",
    purpose: "Exercise deterministic 429 backoff and eventual page success",
    expectedRisk: "NONE_OBSERVED", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["http-429", "retry", "backoff"],
  },
  {
    id: "QUOTA_EXHAUSTED", title: "Repeated quota denial",
    purpose: "Exhaust bounded requests and preserve partial evidence",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["http-429", "bounded-retry", "unknown"],
  },
  {
    id: "PARTIAL_DIRECTORY", title: "Page collection truncated",
    purpose: "Fail after partial user page and never call population complete",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["partial", "no-silent-success", "source-coverage"],
  },
  {
    id: "REPORTS_UNAVAILABLE", title: "Audit scopes denied",
    purpose: "Preserve missing Reports API activity without changing Directory coverage",
    expectedRisk: "UNKNOWN", expectedCoverage: "DENIED",
    requiredResources: ["LOGIN_AUDIT", "ADMIN_AUDIT"],
    producesGoogleTraffic: false, customerTenantAuthenticated: false,
    containsRealUserData: false,
    gates: ["reports-403", "capability-specific"],
  },
  {
    id: "REPORTS_PARTIAL", title: "Audit feed partial",
    purpose: "Reject overconfident audit conclusions when one page is lost",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["LOGIN_AUDIT"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["reports", "pagination", "partial"],
  },
  {
    id: "UNKNOWN_MFA", title: "Unsupported 2SV fields",
    purpose: "Distinguish missing MFA attributes from verified unenrolled identities",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["missing-field", "unknown-not-healthy"],
  },
  {
    id: "SUSPENDED_ADMIN", title: "Suspended privileged account",
    purpose: "Require contextual privileged account review, not automatic suspension",
    expectedRisk: "POTENTIAL", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["role-state-conflict", "no-auto-remediation"],
  },
  {
    id: "NO_IDENTITIES", title: "Empty Directory response",
    purpose: "Check zero-record inventory semantics without asserting tenant has no users",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["empty", "score-null"],
  },
  {
    id: "MALFORMED_PAGE", title: "Malformed JSON response",
    purpose: "Safely reject bad page content without exposing token or URL",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["bad-json", "no-crash", "no-secrets"],
  },
  {
    id: "REPEATED_PAGE", title: "Repeated page token",
    purpose: "Detect provider pagination loops and block duplicate evidence",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["pagination-cycle", "bounded-work"],
  },
  {
    id: "TRANSPORT_TIMEOUT", title: "Transient service unavailable",
    purpose: "Use bounded transport retries and flag exhausted error",
    expectedRisk: "UNKNOWN", expectedCoverage: "PARTIAL",
    requiredResources: ["USERS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["http-503", "bounded-retry", "no-live"],
  },
  {
    id: "DOMAIN_UNVERIFIED", title: "Domain pending verification",
    purpose: "Report only the observed Directory verification status",
    expectedRisk: "POTENTIAL", expectedCoverage: "LOCAL_COMPLETE",
    requiredResources: ["DOMAINS"], producesGoogleTraffic: false,
    customerTenantAuthenticated: false, containsRealUserData: false,
    gates: ["domain", "no-dns-inference"],
  },
] as const;
function hash(v: unknown) {
  return canonicalGoogleHash(v);
}
function assertId(value: unknown, label: string, limit = 128) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(value) ||
      value.length > limit)
    throw new Error("Invalid Google LAB scenario " + label + ".");
  return value;
}
function clock(v: unknown) {
  if (typeof v !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(v) ||
      !Number.isFinite(Date.parse(v)))
    throw new Error("Invalid LAB scenario timestamp.");
  return new Date(v).toISOString();
}
function scenarioName(v: unknown): GoogleLabScenarioName {
  if (typeof v !== "string" ||
      !GOOGLE_LAB_SCENARIOS.some(x => x.id === v))
    throw new Error("Unknown Google LAB scenario.");
  return v as GoogleLabScenarioName;
}
function syntheticEmail(organizationId: string, ordinal: number) {
  const tenant = createHash("sha256").update(organizationId)
    .digest("hex").slice(0, 12);
  return "fixture-" + ordinal + "@" + tenant + ".example.invalid";
}
function mockUser(
  organizationId: string, ordinal: number,
  checkedAt: string, options: {
    admin?: boolean | null;
    delegated?: boolean | null;
    suspended?: boolean | null;
    enrolled?: boolean | null;
    enforced?: boolean | null;
    stale?: boolean;
  } = {},
): GoogleMockIdentity {
  const id = createHash("sha256").update(organizationId)
    .update(":fixture-user:" + ordinal).digest("hex").slice(0, 26);
  return {
    id, primaryEmail: syntheticEmail(organizationId, ordinal),
    isAdmin: options.admin === undefined ? ordinal === 1 : options.admin,
    isDelegatedAdmin: options.delegated === undefined ?
      false : options.delegated,
    suspended: options.suspended === undefined ?
      false : options.suspended,
    isEnrolledIn2Sv: options.enrolled === undefined ?
      true : options.enrolled,
    isEnforcedIn2Sv: options.enforced === undefined ?
      true : options.enforced,
    creationTime: new Date(Date.parse(checkedAt) -
      365 * 86400000).toISOString(),
    lastLoginTime: new Date(Date.parse(checkedAt) -
      (options.stale ? 365 : 1) * 86400000).toISOString(),
    orgUnitPath: ordinal % 2 ? "/Operations" : "/Engineering",
    aliases: [],
  };
}
function mockDomain(organizationId: string,
  verified = true): GoogleMockDomain {
  const part = createHash("sha256").update(organizationId)
    .digest("hex").slice(0, 14);
  return { domainName: "tenant-" + part + ".example.invalid",
    isPrimary: true, verified };
}
function mockOus(): GoogleMockOrgUnit[] {
  return [
    { orgUnitId: "ou-operations", orgUnitPath: "/Operations",
      parentOrgUnitPath: "/", name: "Operations",
      blockInheritance: false },
    { orgUnitId: "ou-engineering", orgUnitPath: "/Engineering",
      parentOrgUnitPath: "/", name: "Engineering",
      blockInheritance: false },
  ];
}
function mockEvent(
  organizationId: string, checkedAt: string,
  ordinal: number, category: "login" | "admin",
): GoogleMockEvent {
  const qualifier = createHash("sha256")
    .update(organizationId).update(":event:" + category + ordinal)
    .digest("hex").slice(0, 20);
  return {
    id: {
      time: new Date(Date.parse(checkedAt) -
        (ordinal + 1) * 60000).toISOString(),
      uniqueQualifier: qualifier,
      applicationName: category,
    },
    actor: { email: syntheticEmail(organizationId, ordinal + 1) },
    events: [{
      name: category === "login" ?
        "login_success" : "CHANGE_USER_SETTING",
      parameters: [
        { name: "success", boolValue: true },
        { name: "fixture", value: "local-only" },
      ],
    }],
  };
}
export function makeGoogleLabScenario(input: {
  organizationId: string;
  scenario: GoogleLabScenarioName;
  checkedAt: string;
  userCount?: number;
}): GoogleLabScenarioSource {
  const organizationId = assertId(input.organizationId, "organization ID");
  const checkedAt = clock(input.checkedAt);
  const id = scenarioName(input.scenario);
  const maximum = id === "PAGINATED_DIRECTORY" ? 120 : 20;
  const requestedCount = input.userCount ??
    (id === "PAGINATED_DIRECTORY" ? 9 :
      id === "NO_IDENTITIES" ? 0 : 3);
  if (!Number.isSafeInteger(requestedCount) ||
      requestedCount < 0 || requestedCount > maximum)
    throw new Error("Google fixture population exceeds scenario bound.");
  const users: GoogleMockIdentity[] = [];
  for (let i = 0; i < requestedCount; i++) {
    const ordinal = i + 1;
    const privileged = ordinal === 1;
    users.push(mockUser(organizationId, ordinal, checkedAt, {
      admin: privileged,
      delegated: ordinal === 2,
      suspended: id === "SUSPENDED_ADMIN" && privileged,
      enrolled: id === "UNKNOWN_MFA" ? null :
        ["MFA_GAPS", "ADMIN_RISK"].includes(id) && privileged ?
          false : true,
      enforced: id === "UNKNOWN_MFA" ? null :
        ["MFA_GAPS", "ADMIN_RISK"].includes(id) && privileged ?
          false : true,
      stale: id === "ADMIN_RISK" && privileged,
    }));
  }
  const domains = [mockDomain(organizationId,
    id !== "DOMAIN_UNVERIFIED")];
  const orgUnits = mockOus();
  const loginEvents = [
    mockEvent(organizationId, checkedAt, 0, "login"),
    mockEvent(organizationId, checkedAt, 1, "login"),
  ];
  const adminEvents = [
    mockEvent(organizationId, checkedAt, 0, "admin"),
  ];
  const fault = [
    "PERMISSION_DENIED", "QUOTA_EXHAUSTED",
    "PARTIAL_DIRECTORY", "REPORTS_UNAVAILABLE",
    "REPORTS_PARTIAL", "UNKNOWN_MFA",
    "NO_IDENTITIES", "MALFORMED_PAGE",
    "REPEATED_PAGE", "TRANSPORT_TIMEOUT",
  ].includes(id);
  const base = {
    schema: "cyberpilot.google.lab.scenario.v1" as const,
    id, organizationId, checkedAt,
    users, domains, orgUnits, loginEvents, adminEvents,
    expectedPartial: fault,
    expectedPermissionFailure: [
      "PERMISSION_DENIED", "REPORTS_UNAVAILABLE",
    ].includes(id),
    expectedQuotaFailure: id === "QUOTA_EXHAUSTED",
    description: GOOGLE_LAB_SCENARIOS.find(s =>
      s.id === id)!.purpose,
    requiresRealProvider: false as const,
    containsCustomerEmails: false as const,
    userIdsGeneratedLocally: true as const,
  };
  return { ...base, sourceDigest: hash(base) };
}
export function verifyGoogleLabScenario(source: GoogleLabScenarioSource) {
  const { sourceDigest, ...canonical } = source;
  const issues: string[] = [];
  if (hash(canonical) !== sourceDigest)
    issues.push("Fixture content changed.");
  if (source.requiresRealProvider ||
      source.containsCustomerEmails ||
      !source.userIdsGeneratedLocally)
    issues.push("Fixture claims real identities or external connection.");
  if (source.users.some(u =>
    !u.primaryEmail.endsWith(".example.invalid")))
    issues.push("Fixture contains unexpected email domain.");
  if (source.users.length > 120 ||
      source.loginEvents.length > 100 ||
      source.adminEvents.length > 100)
    issues.push("Fixture population out of bounds.");
  if (!GOOGLE_LAB_SCENARIOS.some(x => x.id === source.id))
    issues.push("Unknown fixture scenario.");
  return { valid: issues.length === 0, issues };
}
export function scenarioFaults(
  source: GoogleLabScenarioSource,
): GoogleLabFault[] {
  if (!verifyGoogleLabScenario(source).valid)
    throw new Error("Cannot derive fault from altered scenario.");
  const fault = (
    resource: GoogleApiResource, page: number,
    kind: GoogleLabFault["kind"], maxActivations = 100,
    status = 500,
  ): GoogleLabFault => ({
    resource, page, kind, maxActivations, status,
    affectsRealGoogle: false,
  });
  switch (source.id) {
    case "PERMISSION_DENIED":
      return [fault("USERS", 0, "HTTP_403", 100, 403)];
    case "QUOTA_THEN_RECOVER":
      return [fault("USERS", 0, "HTTP_429_ONCE", 1, 429)];
    case "QUOTA_EXHAUSTED":
      return [fault("USERS", 0, "HTTP_429", 100, 429)];
    case "PARTIAL_DIRECTORY":
      return [fault("USERS", 1, "HTTP_503", 100, 503)];
    case "REPORTS_UNAVAILABLE":
      return [
        fault("LOGIN_AUDIT", 0, "HTTP_403", 100, 403),
        fault("ADMIN_AUDIT", 0, "HTTP_403", 100, 403),
      ];
    case "REPORTS_PARTIAL":
      return [fault("LOGIN_AUDIT", 1, "HTTP_503", 100, 503)];
    case "MALFORMED_PAGE":
      return [fault("USERS", 0, "BAD_JSON")];
    case "REPEATED_PAGE":
      return [fault("USERS", 1, "PAGE_CYCLE")];
    case "TRANSPORT_TIMEOUT":
      return [fault("USERS", 0, "TIMEOUT")];
    case "NO_IDENTITIES":
      return [fault("USERS", 0, "NO_ITEMS")];
    default:
      return [];
  }
}
export function defaultScenarioPolicy(
  source: GoogleLabScenarioSource,
): GoogleTransportPolicy {
  if (!verifyGoogleLabScenario(source).valid)
    throw new Error("Invalid LAB scenario.");
  return parseGoogleTransportPolicy({
    pageSize: source.id === "PAGINATED_DIRECTORY" ||
      source.id === "PARTIAL_DIRECTORY" ||
      source.id === "REPEATED_PAGE" ? 2 :
      source.id === "REPORTS_PARTIAL" ? 1 : 100,
    maxPagesPerResource: 12,
    maxTotalRequests: 70,
    maxRetriesPerPage: 2,
    timeoutMs: 2500,
    maxElapsedMs: 30000,
    minBackoffMs: 0,
    maxBackoffMs: 0,
    auditStartTime: new Date(Date.parse(source.checkedAt) -
      86400000).toISOString(),
    auditEndTime: source.checkedAt,
    includeReports: true,
  });
}
function pagesFor(
  source: GoogleLabScenarioSource,
  resource: GoogleApiResource,
): unknown[] {
  switch (resource) {
    case "USERS": return source.users;
    case "DOMAINS": return source.domains;
    case "ORG_UNITS": return source.orgUnits;
    case "LOGIN_AUDIT": return source.loginEvents;
    case "ADMIN_AUDIT": return source.adminEvents;
    default: return [];
  }
}
function keyFor(resource: GoogleApiResource) {
  return {
    USERS: "users", DOMAINS: "domains", ORG_UNITS: "organizationUnits",
    LOGIN_AUDIT: "items", ADMIN_AUDIT: "items",
  }[resource];
}
function resourceFromUrl(url: URL): GoogleApiResource {
  const path = url.pathname;
  if (path === "/admin/directory/v1/users") return "USERS";
  if (path.endsWith("/domains") &&
      path.startsWith("/admin/directory/v1/customer/"))
    return "DOMAINS";
  if (path.endsWith("/orgunits") &&
      path.startsWith("/admin/directory/v1/customer/"))
    return "ORG_UNITS";
  if (path === "/admin/reports/v1/activity/users/all/applications/login")
    return "LOGIN_AUDIT";
  if (path === "/admin/reports/v1/activity/users/all/applications/admin")
    return "ADMIN_AUDIT";
  throw new Error("Unknown or prohibited mock Google resource path.");
}
function tokenFor(
  source: GoogleLabScenarioSource, resource: GoogleApiResource,
  nextPage: number,
) {
  return Buffer.from(
    source.id + ":" + resource + ":" + nextPage, "utf8")
    .toString("base64url");
}
function decodeToken(
  source: GoogleLabScenarioSource,
  resource: GoogleApiResource, raw: string | null,
) {
  if (!raw) return 0;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(raw))
    throw new Error("Malformed synthetic pagination token.");
  let decoded: string;
  try { decoded = Buffer.from(raw, "base64url").toString("utf8"); }
  catch { throw new Error("Invalid synthetic pagination token."); }
  const prefix = source.id + ":" + resource + ":";
  if (!decoded.startsWith(prefix)) 
    throw new Error("Cross-resource page replay rejected.");
  const number = decoded.slice(prefix.length);
  if (!/^\d{1,4}$/.test(number) || Number(number) > 100)
    throw new Error("Page number outside fixture bounds.");
  return Number(number);
}
function mockResponse(status: number, body: string,
  headers: Record<string, string> = {}) {
  return {
    status, ok: status >= 200 && status < 300,
    headers: {
      get: (key: string) => headers[key.toLowerCase()] ?? null,
    },
    text: async () => body,
  };
}
export function buildGoogleLabSimulation(
  source: GoogleLabScenarioSource,
  policy: GoogleTransportPolicy = defaultScenarioPolicy(source),
): GoogleLabSimulation {
  if (!verifyGoogleLabScenario(source).valid)
    throw new Error("Cannot run altered fixture.");
  const attempts = new Map<string, number>();
  const counts = {
    USERS: 0, DOMAINS: 0, ORG_UNITS: 0,
    LOGIN_AUDIT: 0, ADMIN_AUDIT: 0,
  };
  const transcript: GoogleLabMockTrace[] = [];
  const faults = scenarioFaults(source);
  const fetcher: GoogleFetcher = async (rawUrl, options) => {
    if (options.method !== "GET" || options.redirect !== "error")
      throw new Error("Google LAB fixtures never perform writes or redirects.");
    const url = validateGoogleUrl(new URL(rawUrl));
    const resource = resourceFromUrl(url);
    const page = decodeToken(
      source, resource, url.searchParams.get("pageToken"));
    if (options.signal.aborted)
      throw new Error("Synthetic Google operation was cancelled.");
    const expected = buildGoogleResourceUrl(
      resource, "my_customer", policy,
      page ? tokenFor(source, resource, page) : null);
    if (url.toString() !== expected.toString())
      throw new Error("Mock request differs from approved Admin SDK path.");
    const signature = resource + ":" + page;
    const count = (attempts.get(signature) ?? 0) + 1;
    attempts.set(signature, count);
    counts[resource]++;
    const fault = faults.find(f => f.resource === resource &&
      f.page === page && count <= f.maxActivations);
    const items = pagesFor(source, resource);
    const canPage = resource === "USERS" ||
      resource === "LOGIN_AUDIT" || resource === "ADMIN_AUDIT";
    const pageSize = canPage ? policy.pageSize : Math.max(1, items.length);
    const offset = page * pageSize;
    const rows = items.slice(offset, offset + pageSize);
    const next = canPage && offset + rows.length < items.length ?
      tokenFor(source, resource, page + 1) : null;
    let status = 200;
    let body = "";
    const headers: Record<string, string> = {};
    if (fault?.kind === "HTTP_403" ||
        fault?.kind === "HTTP_429" ||
        fault?.kind === "HTTP_429_ONCE" ||
        fault?.kind === "HTTP_503" ||
        fault?.kind === "TIMEOUT") {
      status = fault.kind === "TIMEOUT" ? 503 : fault.status;
      if (status === 429) headers["retry-after"] = "0";
      body = JSON.stringify({
        error: { status, message: "synthetic-fixture-error" },
      });
    } else if (fault?.kind === "BAD_JSON") {
      body = "{malformed-fixture-json";
    } else {
      const payload: Record<string, unknown> = {
        [keyFor(resource)]:
          fault?.kind === "NO_ITEMS" ? [] : rows,
      };
      if (next) payload.nextPageToken = next;
      if (fault?.kind === "PAGE_CYCLE")
        payload.nextPageToken = tokenFor(source, resource, page);
      body = JSON.stringify(payload);
    }
    transcript.push({
      schema: "cyberpilot.google.mock.trace.v1",
      scenario: source.id,
      organizationId: source.organizationId,
      requestedAt: source.checkedAt, resource, page,
      status, attempt: count,
      responseDigest: hash({ resource, page, status,
        body }),
      returningNextPage: !!next,
      durationVirtualMs: 0,
      usedFixtureOnly: true,
      bearerTokenLogged: false,
      rawAuthorizationHeadersLogged: false,
    });
    return mockResponse(status, body, headers);
  };
  return {
    scenario: source, fetcher, transcript, counts,
    faults, reset: () => {
      attempts.clear();
      transcript.length = 0;
      for (const r of resources) counts[r] = 0;
    },
    inspect: () => ({
      scenario: source.id,
      requests: transcript.length,
      failures: transcript.filter(t => t.status !== 200).length,
      pages: transcript.filter(t => t.status === 200).length,
      maxRequestsPerResource: Math.max(...Object.values(counts)),
      liveRequests: 0 as const, credentialLeaks: 0 as const,
      transcriptDigest: hash(transcript),
    }),
  };
}
export function summarizeGoogleLabScenarios() {
  return GOOGLE_LAB_SCENARIOS.map((scenario, index) => ({
    index, id: scenario.id, title: scenario.title,
    purpose: scenario.purpose, risk: scenario.expectedRisk,
    coverage: scenario.expectedCoverage, gates: [...scenario.gates],
    providerTraffic: 0 as const,
    needsCustomerTenant: false as const,
    realProviderAuthorized: false as const,
  }));
}
export function validateGoogleMockTrace(
  source: GoogleLabScenarioSource, trace: GoogleLabMockTrace[],
) {
  const issues: string[] = [];
  if (!verifyGoogleLabScenario(source).valid)
    issues.push("SCENARIO_DIGEST_INVALID");
  if (trace.length > 200)
    issues.push("TRACE_EXCEEDS_SAFE_LIMIT");
  for (const [index, request] of trace.entries()) {
    if (request.organizationId !== source.organizationId ||
        request.scenario !== source.id)
      issues.push("TENANT_SCOPE_MISMATCH_" + index);
    if (!resources.includes(request.resource) ||
        request.page < 0 || request.page > 100)
      issues.push("RESOURCE_OUT_OF_BOUNDS_" + index);
    if (!request.usedFixtureOnly ||
        request.bearerTokenLogged ||
        request.rawAuthorizationHeadersLogged)
      issues.push("GOOGLE_LIVE_OR_TOKEN_LEAK_" + index);
  }
  return {
    valid: issues.length === 0, issues,
    total: trace.length,
    errors: trace.filter(t => t.status !== 200).length,
    requestDigest: hash(trace),
    realGoogleRequests: 0 as const,
  };
}
