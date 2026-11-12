import { createHash } from "node:crypto";
import {
  CAPABILITIES, GoogleContractError, boundedString, record,
  normalizeBatch, extractReportEvents, type GoogleCapability,
  type GoogleDirectoryObservation, type GoogleEntitlement,
  type ReportsEvent,
} from "./directory-contract";

export type GoogleApiResource =
  "USERS" | "DOMAINS" | "ORG_UNITS" |
  "LOGIN_AUDIT" | "ADMIN_AUDIT";
export type GoogleFailureCategory =
  "PERMISSION" | "QUOTA" | "TRANSPORT" |
  "MALFORMED" | "PARTIAL" | "UNAVAILABLE";
export type GoogleApiFailure = {
  resource: GoogleApiResource;
  capability: GoogleCapability;
  category: GoogleFailureCategory;
  status: number | null;
  retryable: boolean;
  retryAfterMs: number | null;
  summary: string;
  requestCount: number;
  pagesRead: number;
};
export type GoogleFetchResponse = {
  status: number;
  ok: boolean;
  headers: { get(key: string): string | null };
  text(): Promise<string>;
};
export type GoogleFetcher = (url: string, options: {
  method: "GET"; headers: Record<string, string>;
  signal: AbortSignal; redirect: "error";
}) => Promise<GoogleFetchResponse>;
export type GoogleTransportPolicy = {
  maxPagesPerResource: number;
  pageSize: number;
  maxTotalRequests: number;
  maxRetriesPerPage: number;
  maxResponseBytes: number;
  timeoutMs: number;
  maxElapsedMs: number;
  minBackoffMs: number;
  maxBackoffMs: number;
  auditStartTime: string | null;
  auditEndTime: string | null;
  includeReports: boolean;
};
export type GoogleTransportEnvironment = {
  token: string;
  customerId: string;
  organizationId: string;
  checkedAt: string;
  source: "SYNTHETIC_FIXTURE" | "GOOGLE_DIRECTORY";
  consentVerifiedByCaller: boolean;
  liveProviderAllowedByCaller: boolean;
};
export type GoogleApiPage = {
  resource: GoogleApiResource;
  page: number;
  count: number;
  nextPageTokenPresent: boolean;
  bodyDigest: string;
  httpStatus: number;
  retryCount: number;
  durationMs: number;
};
export type GooglePartialCollection = {
  resource: GoogleApiResource;
  capability: GoogleCapability;
  items: unknown[];
  pages: GoogleApiPage[];
  failures: GoogleApiFailure[];
  truncated: boolean;
  reliable: boolean;
  requestCount: number;
  exhausted: boolean;
  paginationCycleDetected: boolean;
};
export type GoogleCollectionResult = {
  schema: "cyberpilot.google.collection.v1";
  organizationId: string;
  customerIdHash: string;
  checkedAt: string;
  policy: GoogleTransportPolicy;
  resourceCollections: Array<{
    resource: GoogleApiResource;
    count: number;
    pagesRead: number;
    truncated: boolean;
    requestCount: number;
    failureCategory: GoogleFailureCategory | null;
    permissionAvailable: boolean;
  }>;
  observation: GoogleDirectoryObservation;
  failures: GoogleApiFailure[];
  requestCount: number;
  providerContacted: boolean;
  evidenceIncomplete: boolean;
  tokenRetained: false;
  accountWrites: 0;
  externalLiveVerified: false;
};
const BASE = "https://admin.googleapis.com";
const RESOURCE = {
  USERS: {
    path: "/admin/directory/v1/users", key: "users",
    capability: "DIRECTORY_USERS", maxRows: 3000,
  },
  DOMAINS: {
    path: "/admin/directory/v1/customer/my_customer/domains", key: "domains",
    capability: "DIRECTORY_DOMAINS", maxRows: 300,
  },
  ORG_UNITS: {
    path: "/admin/directory/v1/customer/my_customer/orgunits",
    key: "organizationUnits",
    capability: "DIRECTORY_ORGANIZATION_UNITS", maxRows: 500,
  },
  LOGIN_AUDIT: {
    path: "/admin/reports/v1/activity/users/all/applications/login",
    key: "items", capability: "REPORTS_LOGIN", maxRows: 3000,
  },
  ADMIN_AUDIT: {
    path: "/admin/reports/v1/activity/users/all/applications/admin",
    key: "items", capability: "REPORTS_ADMIN", maxRows: 3000,
  },
} as const satisfies Record<GoogleApiResource, {
  path: string; key: string; capability: GoogleCapability;
  maxRows: number;
}>;
export const GOOGLE_READ_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.domain.readonly",
  "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
] as const;
const DEFAULT: GoogleTransportPolicy = {
  maxPagesPerResource: 10, pageSize: 100,
  maxTotalRequests: 80, maxRetriesPerPage: 2,
  maxResponseBytes: 262144, timeoutMs: 5000,
  maxElapsedMs: 60000, minBackoffMs: 250,
  maxBackoffMs: 3000, auditStartTime: null,
  auditEndTime: null, includeReports: true,
};
export class GoogleTransportError extends Error {
  constructor(
    public readonly category: GoogleFailureCategory,
    message: string,
    public readonly httpStatus: number | null = null,
    public readonly retryable = false,
    public readonly retryAfterMs: number | null = null,
  ) { super(message); this.name = "GoogleTransportError"; }
}
function fieldInteger(input: unknown, name: string,
  low: number, high: number) {
  if (typeof input !== "number" ||
      !Number.isSafeInteger(input) || input < low || input > high)
    throw new GoogleContractError("INVALID",
      "Invalid Google " + name + " limit.");
  return input;
}
function dateField(value: unknown, name: string) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    throw new GoogleContractError("INVALID",
      "Invalid Google " + name + ".");
  return new Date(value).toISOString();
}
export function parseGoogleTransportPolicy(raw: unknown = {}) {
  const input = record(raw, "transport policy");
  const keys = [...Object.keys(DEFAULT)];
  if (Object.keys(input).some(key => !keys.includes(key)))
    throw new GoogleContractError("INVALID",
      "Unknown Google transport option.");
  const policy: GoogleTransportPolicy = {
    maxPagesPerResource: fieldInteger(input.maxPagesPerResource ??
      DEFAULT.maxPagesPerResource, "pages", 1, 30),
    pageSize: fieldInteger(input.pageSize ?? DEFAULT.pageSize,
      "page size", 1, 500),
    maxTotalRequests: fieldInteger(input.maxTotalRequests ??
      DEFAULT.maxTotalRequests, "request count", 1, 200),
    maxRetriesPerPage: fieldInteger(input.maxRetriesPerPage ??
      DEFAULT.maxRetriesPerPage, "retries", 0, 6),
    maxResponseBytes: fieldInteger(input.maxResponseBytes ??
      DEFAULT.maxResponseBytes, "response bytes", 1024, 1048576),
    timeoutMs: fieldInteger(input.timeoutMs ?? DEFAULT.timeoutMs,
      "timeout", 100, 30000),
    maxElapsedMs: fieldInteger(input.maxElapsedMs ?? DEFAULT.maxElapsedMs,
      "total deadline", 1000, 300000),
    minBackoffMs: fieldInteger(input.minBackoffMs ?? DEFAULT.minBackoffMs,
      "minimum backoff", 0, 30000),
    maxBackoffMs: fieldInteger(input.maxBackoffMs ?? DEFAULT.maxBackoffMs,
      "maximum backoff", 0, 60000),
    auditStartTime: dateField(input.auditStartTime ??
      DEFAULT.auditStartTime, "audit start"),
    auditEndTime: dateField(input.auditEndTime ??
      DEFAULT.auditEndTime, "audit end"),
    includeReports: input.includeReports === undefined ?
      DEFAULT.includeReports : input.includeReports === true,
  };
  if (input.includeReports !== undefined &&
      typeof input.includeReports !== "boolean")
    throw new GoogleContractError("INVALID", "Invalid report flag.");
  if (policy.minBackoffMs > policy.maxBackoffMs ||
      (policy.auditStartTime && policy.auditEndTime &&
       policy.auditStartTime > policy.auditEndTime))
    throw new GoogleContractError("INVALID",
      "Contradictory Google collection deadlines.");
  if (policy.maxElapsedMs < policy.timeoutMs)
    throw new GoogleContractError("INVALID",
      "Total budget cannot be shorter than a request timeout.");
  return policy;
}
export function sanitizeGoogleFailure(resource: GoogleApiResource,
  error: unknown, requestCount: number, pagesRead: number): GoogleApiFailure {
  const capability = RESOURCE[resource].capability;
  if (error instanceof GoogleTransportError) {
    return {
      resource, capability, category: error.category,
      status: error.httpStatus, retryable: error.retryable,
      retryAfterMs: error.retryAfterMs, summary: error.message,
      requestCount, pagesRead,
    };
  }
  return {
    resource, capability, category: "TRANSPORT",
    status: null, retryable: false, retryAfterMs: null,
    summary: "Unclassified connection or cancellation failure.",
    requestCount, pagesRead,
  };
}
function safeStatus(status: number) {
  if (status === 401 || status === 403)
    return new GoogleTransportError("PERMISSION",
      "Google read permission denied or credential expired.", status);
  if (status === 429)
    return new GoogleTransportError("QUOTA",
      "Google request quota exceeded.", status, true);
  if ([408, 500, 502, 503, 504].includes(status))
    return new GoogleTransportError("TRANSPORT",
      "Transient Google service error.", status, true);
  return new GoogleTransportError("UNAVAILABLE",
    "Google data endpoint returned a non-success result.", status);
}
export function safeRetryAfter(value: string | null, limit: number) {
  if (value === null) return null;
  if (!/^\d{1,7}$/.test(value)) return null;
  return Math.min(Number(value) * 1000, limit);
}
export function deterministicBackoff(attempt: number,
  policy: GoogleTransportPolicy, retryAfterMs: number | null) {
  const exponential = policy.minBackoffMs * 2 ** Math.max(0, attempt);
  return Math.min(policy.maxBackoffMs,
    Math.max(exponential, retryAfterMs ?? 0));
}
export function validateGoogleUrl(url: URL) {
  if (url.origin !== BASE || url.username || url.password ||
      url.hash || !url.pathname.startsWith("/admin/") ||
      url.pathname.includes(".."))
    throw new GoogleContractError("INVALID",
      "Google request target must remain on the Admin SDK origin.");
  for (const key of url.searchParams.keys())
    if (!["customer", "maxResults", "pageToken", "projection",
      "viewType", "orgUnitPath", "type", "startTime",
      "endTime"].includes(key))
      throw new GoogleContractError("INVALID",
        "Unexpected Google query parameter.");
  return url;
}
export function buildGoogleResourceUrl(
  resource: GoogleApiResource,
  customerId: string,
  policy: GoogleTransportPolicy,
  pageToken: string | null = null,
) {
  const config = RESOURCE[resource];
  if (!config)
    throw new GoogleContractError("INVALID", "Unknown Google resource.");
  const customer = boundedString(customerId, "customer ID", 150);
  if (!/^(my_customer|[A-Za-z0-9_-]{5,150})$/.test(customer))
    throw new GoogleContractError("INVALID",
      "Invalid Google customer ID.");
  const url = new URL(config.path, BASE);
  if (resource === "USERS") {
    url.searchParams.set("customer", customer);
    url.searchParams.set("projection", "full");
    url.searchParams.set("viewType", "admin_view");
  } else if (resource === "DOMAINS" || resource === "ORG_UNITS") {
    url.pathname = config.path.replace("my_customer", customer);
    if (resource === "ORG_UNITS") url.searchParams.set("type", "all");
  } else {
    if (policy.auditStartTime)
      url.searchParams.set("startTime", policy.auditStartTime);
    if (policy.auditEndTime)
      url.searchParams.set("endTime", policy.auditEndTime);
  }
  if (resource !== "DOMAINS" && resource !== "ORG_UNITS")
    url.searchParams.set("maxResults", String(policy.pageSize));
  if (pageToken !== null) {
    if (resource === "DOMAINS" || resource === "ORG_UNITS")
      throw new GoogleContractError("INVALID",
        "This Google resource is not paginated by page token.");
    const token = boundedString(pageToken, "page token", 2048);
    if (!/^[A-Za-z0-9_+\/=.-]+$/.test(token))
      throw new GoogleContractError("INVALID",
        "Untrusted Google page token.");
    url.searchParams.set("pageToken", token);
  }
  return validateGoogleUrl(url);
}
export function decodeGoogleJson(text: string, maxBytes: number) {
  if (Buffer.byteLength(text, "utf8") > maxBytes)
    throw new GoogleTransportError("MALFORMED",
      "Google page exceeds configured response bound.");
  let result: unknown;
  try { result = JSON.parse(text); }
  catch {
    throw new GoogleTransportError("MALFORMED",
      "Google returned invalid JSON.");
  }
  return record(result, "API response");
}
export function decodePageItems(
  resource: GoogleApiResource, payload: Record<string, unknown>,
) {
  const key = RESOURCE[resource].key;
  const items = payload[key] ?? [];
  if (!Array.isArray(items) || items.length > 500)
    throw new GoogleTransportError("MALFORMED",
      "Google page contains invalid item list.");
  for (const item of items)
    record(item, "page item");
  const nextPageToken = payload.nextPageToken;
  if (nextPageToken !== undefined && nextPageToken !== null &&
      typeof nextPageToken !== "string")
    throw new GoogleTransportError("MALFORMED",
      "Google pagination token is not a string.");
  if (typeof nextPageToken === "string" &&
      nextPageToken.length > 2048)
    throw new GoogleTransportError("MALFORMED",
      "Google pagination token is oversized.");
  return { items, nextPageToken:
    typeof nextPageToken === "string" && nextPageToken ?
      nextPageToken : null };
}
export function createGoogleTransport(options: {
  fetcher: GoogleFetcher;
  sleep?: (ms: number) => Promise<void>;
  clock?: () => number;
}) {
  if (typeof options.fetcher !== "function")
    throw new GoogleContractError("INVALID",
      "A trusted injectable Google fetcher is required.");
  const sleep = options.sleep ??
    (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  const clock = options.clock ?? (() => Date.now());
  async function page(
    url: URL, token: string, policy: GoogleTransportPolicy,
    budget: { used: number; startedAt: number },
  ) {
    for (let attempt = 0; attempt <= policy.maxRetriesPerPage; attempt++) {
      if (budget.used >= policy.maxTotalRequests ||
          clock() - budget.startedAt >= policy.maxElapsedMs)
        throw new GoogleTransportError("PARTIAL",
          "Google collection budget exhausted.");
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), policy.timeoutMs);
      budget.used++;
      const start = clock();
      try {
        const response = await options.fetcher(url.toString(), {
          method: "GET", redirect: "error",
          signal: controller.signal,
          headers: {
            Authorization: "Bearer " + token,
            Accept: "application/json",
          },
        });
        if (!response.ok) {
          const failure = safeStatus(response.status);
          const retryAfter = safeRetryAfter(
            response.headers.get("retry-after"), policy.maxBackoffMs);
          if (!failure.retryable || attempt >= policy.maxRetriesPerPage)
            throw new GoogleTransportError(failure.category,
              failure.message, response.status, false, retryAfter);
          const pause = deterministicBackoff(attempt,
            policy, retryAfter);
          if (clock() + pause - budget.startedAt >= policy.maxElapsedMs)
            throw new GoogleTransportError("PARTIAL",
              "No time remaining to retry Google request.");
          await sleep(pause);
          continue;
        }
        const body = await response.text();
        const parsed = decodeGoogleJson(body, policy.maxResponseBytes);
        return {
          body: parsed, hash: createHash("sha256")
            .update(body).digest("hex"),
          status: response.status, retries: attempt,
          durationMs: Math.max(0, clock() - start),
        };
      } catch (error) {
        if (error instanceof GoogleTransportError) throw error;
        if (attempt >= policy.maxRetriesPerPage)
          throw new GoogleTransportError("TRANSPORT",
            "Google read timed out or failed.", null, false);
        const pause = deterministicBackoff(attempt, policy, null);
        if (clock() + pause - budget.startedAt >= policy.maxElapsedMs)
          throw new GoogleTransportError("PARTIAL",
            "No time remaining for transport retry.");
        await sleep(pause);
      } finally {
        clearTimeout(timeout);
      }
    }
    throw new GoogleTransportError("TRANSPORT",
      "Google retry policy exhausted.");
  }
  async function collect(
    resource: GoogleApiResource, customerId: string, token: string,
    policy: GoogleTransportPolicy,
    budget: { used: number; startedAt: number },
  ): Promise<GooglePartialCollection> {
    const config = RESOURCE[resource];
    const items: unknown[] = [], pages: GoogleApiPage[] = [];
    const failures: GoogleApiFailure[] = [];
    const seenTokens = new Set<string>();
    let nextPageToken: string | null = null;
    let exhausted = false, paginationCycleDetected = false;
    const initialUsed = budget.used;
    for (let pageIndex = 0;
      pageIndex < policy.maxPagesPerResource; pageIndex++) {
      try {
        const url = buildGoogleResourceUrl(
          resource, customerId, policy, nextPageToken);
        const response = await page(url, token, policy, budget);
        const decoded = decodePageItems(resource, response.body);
        if (items.length + decoded.items.length > config.maxRows)
          throw new GoogleTransportError("PARTIAL",
            "Google collection exceeded safe row capacity.");
        items.push(...decoded.items);
        pages.push({
          resource, page: pageIndex + 1, count: decoded.items.length,
          nextPageTokenPresent: !!decoded.nextPageToken,
          bodyDigest: response.hash, httpStatus: response.status,
          retryCount: response.retries, durationMs: response.durationMs,
        });
        if (!decoded.nextPageToken) {
          exhausted = true;
          break;
        }
        if (seenTokens.has(decoded.nextPageToken)) {
          paginationCycleDetected = true;
          throw new GoogleTransportError("PARTIAL",
            "Repeated Google page token rejected.");
        }
        seenTokens.add(decoded.nextPageToken);
        nextPageToken = decoded.nextPageToken;
        if (resource === "DOMAINS" || resource === "ORG_UNITS")
          throw new GoogleTransportError("MALFORMED",
            "Non-paginated Google resource returned nextPageToken.");
      } catch (error) {
        failures.push(sanitizeGoogleFailure(resource,
          error, budget.used - initialUsed, pages.length));
        break;
      }
    }
    const truncated = !exhausted ||
      failures.length > 0 || paginationCycleDetected;
    return {
      resource, capability: config.capability, items, pages,
      failures, truncated,
      reliable: exhausted && !truncated && failures.length === 0,
      requestCount: budget.used - initialUsed,
      exhausted, paginationCycleDetected,
    };
  }
  return { page, collect };
}
export function inspectGoogleEnvironment(
  env: GoogleTransportEnvironment,
  options: { allowRealProvider?: boolean } = {},
) {
  const organizationId = boundedString(env.organizationId,
    "organization ID", 128);
  const customerId = boundedString(env.customerId, "customer ID", 150);
  const checkedAt = boundedString(env.checkedAt, "collection time", 60);
  if (!Number.isFinite(Date.parse(checkedAt)))
    throw new GoogleContractError("INVALID", "Invalid collection time.");
  if (typeof env.token !== "string" || !env.token ||
      env.token.length > 8192 || /[\u0000-\u001f\u007f]/.test(env.token))
    throw new GoogleContractError("INVALID",
      "Google bearer credential missing or invalid.");
  if (env.source !== "SYNTHETIC_FIXTURE" &&
      env.source !== "GOOGLE_DIRECTORY")
    throw new GoogleContractError("INVALID",
      "Unsupported provider evidence source.");
  if (env.consentVerifiedByCaller !== true)
    throw new GoogleContractError("INVALID",
      "Explicit administrator consent must be documented before collection.");
  if (env.source === "GOOGLE_DIRECTORY" &&
      (options.allowRealProvider !== true ||
       env.liveProviderAllowedByCaller !== true))
    throw new GoogleContractError("INVALID",
      "LIVE Google Directory explicitly disabled for offline development.");
  return { organizationId, customerId, checkedAt,
    fixtureMode: env.source === "SYNTHETIC_FIXTURE",
    liveProviderVerified: false as const };
}
export function createFixtureFetch(
  fixture: Record<string, Array<Record<string, unknown>>>,
): GoogleFetcher {
  return async (url, options) => {
    const parsed = validateGoogleUrl(new URL(url));
    if (options.method !== "GET" || options.redirect !== "error")
      throw new GoogleTransportError("MALFORMED",
        "Fixture rejects writes and redirects.");
    const token = parsed.searchParams.get("pageToken") ?? "";
    const key = parsed.pathname + "?" + token;
    const pages = fixture[key];
    if (!Array.isArray(pages) || pages.length !== 1)
      return {
        status: 404, ok: false, headers: { get: () => null },
        text: async () => "{}",
      };
    return {
      status: 200, ok: true,
      headers: { get: () => null },
      text: async () => JSON.stringify(pages[0]),
    };
  };
}
export async function collectGoogleWorkspace(input: {
  environment: GoogleTransportEnvironment;
  policy?: unknown;
  fetcher: GoogleFetcher;
  sleep?: (ms: number) => Promise<void>;
  clock?: () => number;
  allowRealProvider?: boolean;
}) {
  const policy = parseGoogleTransportPolicy(input.policy);
  const env = inspectGoogleEnvironment(input.environment,
    { ...(input.allowRealProvider !== undefined ?
      { allowRealProvider: input.allowRealProvider } : {}) });
  const transport = createGoogleTransport({
    fetcher: input.fetcher,
    ...(input.sleep ? { sleep: input.sleep } : {}),
    ...(input.clock ? { clock: input.clock } : {}),
  });
  const clock = input.clock ?? (() => Date.now());
  const budget = { used: 0, startedAt: clock() };
  const resources: GoogleApiResource[] =
    ["USERS", "DOMAINS", "ORG_UNITS"];
  if (policy.includeReports)
    resources.push("LOGIN_AUDIT", "ADMIN_AUDIT");
  const collections: GooglePartialCollection[] = [];
  for (const resource of resources) {
    collections.push(await transport.collect(resource,
      env.customerId, input.environment.token, policy, budget));
  }
  const collection = (type: GoogleApiResource) =>
    collections.find(entry => entry.resource === type);
  const users = collection("USERS")?.items ?? [];
  const domains = collection("DOMAINS")?.items ?? [];
  const orgUnits = collection("ORG_UNITS")?.items ?? [];
  const reports: ReportsEvent[] = [];
  const failures = collections.flatMap(entry => entry.failures);
  const effectiveCoverage: Record<GoogleCapability, GoogleEntitlement> =
    Object.fromEntries(CAPABILITIES.map(capability =>
      [capability, "UNKNOWN"])) as
      Record<GoogleCapability, GoogleEntitlement>;
  const truncation = Object.fromEntries(CAPABILITIES.map(capability =>
    [capability, false])) as Record<GoogleCapability, boolean>;
  for (const entry of collections) {
    effectiveCoverage[entry.capability] = entry.reliable ?
      "AVAILABLE" : entry.failures.some(f => f.category === "PERMISSION") ?
        "REQUIRES_PERMISSION" : "UNKNOWN";
    truncation[entry.capability] = entry.truncated;
  }
  if (collection("USERS")?.reliable &&
      users.every(row => {
        const value = record(row, "MFA coverage");
        return typeof value.isEnrolledIn2Sv === "boolean" &&
          typeof value.isEnforcedIn2Sv === "boolean";
      }))
    effectiveCoverage.USER_MFA_ATTRIBUTES = "AVAILABLE";
  else effectiveCoverage.USER_MFA_ATTRIBUTES = "UNKNOWN";
  truncation.USER_MFA_ATTRIBUTES = collection("USERS")?.truncated ?? true;
  for (const resource of ["LOGIN_AUDIT", "ADMIN_AUDIT"] as const) {
    const entries = collection(resource)?.items ?? [];
    for (const entry of entries)
      reports.push(...extractReportEvents(entry, env.organizationId,
        resource === "LOGIN_AUDIT" ? "LOGIN" : "ADMIN"));
  }
  const observation = normalizeBatch({
    organizationId: env.organizationId, checkedAt: env.checkedAt,
    source: env.fixtureMode ? "SYNTHETIC_FIXTURE" : "GOOGLE_DIRECTORY",
    users, domains, orgUnits, reports,
    coverage: effectiveCoverage,
    truncation,
    failures: failures.map(f => ({
      capability: f.capability, category: f.category,
      explanation: f.summary, recoverable: f.retryable,
    })),
  });
  const customerIdHash = createHash("sha256").update(env.organizationId)
    .update("\0").update(env.customerId).digest("hex");
  const result: GoogleCollectionResult = {
    schema: "cyberpilot.google.collection.v1",
    organizationId: env.organizationId, customerIdHash,
    checkedAt: env.checkedAt, policy,
    resourceCollections: collections.map(entry => ({
      resource: entry.resource, count: entry.items.length,
      pagesRead: entry.pages.length, truncated: entry.truncated,
      requestCount: entry.requestCount,
      failureCategory: entry.failures[0]?.category ?? null,
      permissionAvailable: entry.reliable,
    })),
    observation, failures, requestCount: budget.used,
    providerContacted: !env.fixtureMode,
    evidenceIncomplete: observation.unknownCapabilities.length > 0,
    tokenRetained: false, accountWrites: 0,
    externalLiveVerified: false,
  };
  return result;
}
