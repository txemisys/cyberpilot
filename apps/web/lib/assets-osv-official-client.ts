import { createHash } from "node:crypto";
import { WorkInputError } from "./remediation-work-input";

export const OSV_API_ORIGIN = "https://api.osv.dev";
export const OSV_QUERY_PATH = "/v1/query";
export type LiveOsvRequest = {
  ecosystem: string;
  name: string;
  version: string;
  expectedPurl?: string | null;
};
export type LiveOsvReference = {
  id: string;
  modified: string | null;
  withdrawn: string | null;
  aliases: string[];
  exactVersionListed: boolean;
  packageIdentityListed: boolean;
  rangesPresent: boolean;
  fingerprint: string;
};
export type LiveOsvPage = {
  references: LiveOsvReference[];
  nextPageToken: string | null;
  httpStatus: number;
  responseBytes: number;
  responseDigest: string;
};
export type LiveOsvQueryResult = {
  schema: "cyberpilot.assets.osv.live.query.v1";
  endpoint: typeof OSV_API_ORIGIN;
  package: LiveOsvRequest;
  checkedAt: string;
  provider: "OSV_DEV_API";
  transport: "HTTPS_FIXED_ENDPOINT";
  status: "COMPLETE" | "TRUNCATED" | "UPSTREAM_ERROR";
  queriedPages: number;
  responseBytes: number;
  vulnerabilities: LiveOsvReference[];
  providerReportedCount: number;
  exactEnumeratedCount: number;
  nonEnumeratedCount: number;
  withdrawnCount: number;
  warnings: string[];
  digest: string;
};
export type LiveOsvClientOptions = {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  timeoutMs?: number;
  maxPages?: number;
  maxResponseBytes?: number;
  maxRecords?: number;
};
type ClientLimits = {
  timeoutMs: number;
  maxPages: number;
  maxResponseBytes: number;
  maxRecords: number;
};
const safePackage = /^[a-zA-Z0-9@_][a-zA-Z0-9@_./+~-]{0,159}$/;
const safeEcosystem = /^[a-zA-Z][a-zA-Z0-9_.:+ -]{0,69}$/;
const safeVersion = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,79}$/;
const safeId = /^[a-zA-Z0-9][a-zA-Z0-9._:+-]{1,119}$/;
const safePurl = /^pkg:[a-z0-9.+-]+\/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]{1,250}$/;
const controls = /[\u0000-\u001f\u007f]/;
function fail(message: string): never {
  throw new WorkInputError("INVALID", message);
}
function bounded(value: number | undefined, defaultValue: number,
  label: string, lower: number, upper: number): number {
  const result = value ?? defaultValue;
  if (!Number.isSafeInteger(result) || result < lower || result > upper)
    fail("Invalid OSV client limit: " + label);
  return result;
}
function limits(options: LiveOsvClientOptions): ClientLimits {
  return {
    timeoutMs: bounded(options.timeoutMs, 5000, "timeout", 100, 15000),
    maxPages: bounded(options.maxPages, 3, "pages", 1, 5),
    maxResponseBytes: bounded(
      options.maxResponseBytes, 524288, "response bytes", 1024, 2097152),
    maxRecords: bounded(options.maxRecords, 100, "records", 1, 500),
  };
}
function digest(value: unknown) {
  return createHash("sha256").update(
    typeof value === "string" ? value : JSON.stringify(value)).digest("hex");
}
function object(value: unknown, where: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    fail("Malformed OSV response at " + where);
  return value as Record<string, unknown>;
}
function optionalDate(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 45 ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value))
    return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString() : null;
}
function stringArray(value: unknown, limit: number) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((x): x is string =>
    typeof x === "string" && x.length <= 120 &&
    safeId.test(x)))].sort().slice(0, limit);
}
export function validateLiveOsvRequest(input: unknown): LiveOsvRequest {
  const raw = object(input, "request");
  if (Object.keys(raw).some(key => ![
    "ecosystem", "name", "version", "expectedPurl",
  ].includes(key))) fail("Unknown OSV query field.");
  const ecosystem = raw.ecosystem;
  const name = raw.name;
  const version = raw.version;
  const expectedPurl = raw.expectedPurl;
  if (typeof ecosystem !== "string" || !safeEcosystem.test(ecosystem) ||
      controls.test(ecosystem))
    fail("Invalid OSV ecosystem.");
  if (typeof name !== "string" || !safePackage.test(name) ||
      controls.test(name) || name.includes("..") || name.includes("//"))
    fail("Invalid OSV package identity.");
  if (typeof version !== "string" || !safeVersion.test(version) ||
      /^(?:latest|current|unknown|any|all)$/i.test(version))
    fail("OSV live query requires an unambiguous version.");
  if (expectedPurl !== undefined && expectedPurl !== null &&
      (typeof expectedPurl !== "string" || !safePurl.test(expectedPurl) ||
        expectedPurl.includes("@")))
    fail("Invalid unversioned package URL.");
  return {
    ecosystem, name, version,
    ...(typeof expectedPurl === "string" ? { expectedPurl } : {}),
  };
}
export function buildLiveOsvPayload(request: LiveOsvRequest,
  pageToken?: string): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    version: request.version,
    package: request.expectedPurl ?
      { purl: request.expectedPurl } :
      { name: request.name, ecosystem: request.ecosystem },
  };
  if (pageToken) {
    if (pageToken.length > 2048 || !/^[A-Za-z0-9_+/=-]+$/.test(pageToken))
      fail("Malformed OSV pagination token.");
    payload.page_token = pageToken;
  }
  return payload;
}
function affectedIdentity(
  vulnerability: Record<string, unknown>, request: LiveOsvRequest,
) {
  const affected = Array.isArray(vulnerability.affected) ?
    vulnerability.affected.slice(0, 100) : [];
  let packageIdentityListed = false;
  let exactVersionListed = false;
  let rangesPresent = false;
  for (const raw of affected) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) continue;
    const entry = raw as Record<string, unknown>;
    if (!entry.package || typeof entry.package !== "object" ||
        Array.isArray(entry.package)) continue;
    const pkg = entry.package as Record<string, unknown>;
    const matches = request.expectedPurl ?
      pkg.purl === request.expectedPurl :
      pkg.ecosystem === request.ecosystem && pkg.name === request.name;
    if (!matches) continue;
    packageIdentityListed = true;
    if (Array.isArray(entry.versions) &&
        entry.versions.includes(request.version))
      exactVersionListed = true;
    if (Array.isArray(entry.ranges) && entry.ranges.length > 0)
      rangesPresent = true;
  }
  return { packageIdentityListed, exactVersionListed, rangesPresent };
}
export function parseLiveOsvPage(
  payload: unknown, request: LiveOsvRequest, rawBody: string,
  status = 200,
): LiveOsvPage {
  const data = object(payload, "query result");
  const vulns = data.vulns === undefined ? [] : data.vulns;
  if (!Array.isArray(vulns) || vulns.length > 500)
    fail("OSV response vulnerability collection exceeds bounds.");
  const references: LiveOsvReference[] = [];
  for (const item of vulns) {
    const raw = object(item, "vulnerability");
    if (typeof raw.id !== "string" || !safeId.test(raw.id))
      fail("OSV response has invalid vulnerability ID.");
    const identity = affectedIdentity(raw, request);
    const canonical = {
      id: raw.id,
      modified: optionalDate(raw.modified),
      withdrawn: raw.withdrawn === undefined ?
        null : optionalDate(raw.withdrawn) ?? "UNKNOWN_WITHDRAWAL",
      aliases: stringArray(raw.aliases, 40),
      ...identity,
    };
    references.push({ ...canonical, fingerprint: digest(canonical) });
  }
  const token = data.next_page_token;
  if (token !== undefined &&
      (typeof token !== "string" || token.length > 2048 ||
        !/^[A-Za-z0-9_+/=-]+$/.test(token)))
    fail("Invalid OSV next_page_token.");
  return {
    references, nextPageToken: typeof token === "string" && token ?
      token : null,
    httpStatus: status,
    responseBytes: Buffer.byteLength(rawBody, "utf8"),
    responseDigest: digest(rawBody),
  };
}
async function fetchPage(request: LiveOsvRequest, pageToken: string | undefined,
  client: typeof fetch, options: ClientLimits,
): Promise<LiveOsvPage> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    timeout = setTimeout(() => controller.abort(), options.timeoutMs);
    const response = await client(OSV_API_ORIGIN + OSV_QUERY_PATH, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(buildLiveOsvPayload(request, pageToken)),
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
    });
    if (!response.ok)
      throw new Error("OSV query failed with status " + response.status);
    const declaredLength = response.headers.get("content-length");
    if (declaredLength && Number(declaredLength) > options.maxResponseBytes)
      throw new Error("OSV response exceeds configured byte budget.");
    const body = await response.text();
    if (Buffer.byteLength(body, "utf8") > options.maxResponseBytes)
      throw new Error("OSV response exceeds configured byte budget.");
    let decoded: unknown;
    try { decoded = JSON.parse(body); }
    catch { throw new Error("Invalid OSV API JSON."); }
    return parseLiveOsvPage(decoded, request, body, response.status);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
export async function queryOfficialOsv(
  input: unknown, options: LiveOsvClientOptions = {},
): Promise<LiveOsvQueryResult> {
  const request = validateLiveOsvRequest(input);
  const settings = limits(options);
  const checkedAt = (options.now?.() ?? new Date()).toISOString();
  const all = new Map<string, LiveOsvReference>();
  const fetchedTokens = new Set<string>();
  const warnings = [
    "OSV query results are provider-reported matches; the API can apply fuzzy version matching.",
    "Only explicit affected.versions enumerations count as literal matches.",
    "OSV API transport over TLS is not a cryptographic signature of advisory provenance.",
    "An empty response does not establish that a package or device is safe.",
    "No inventory device identifier is sent to OSV; only package identity and version.",
  ];
  let next: string | undefined;
  let queriedPages = 0;
  let responseBytes = 0;
  let status: LiveOsvQueryResult["status"] = "COMPLETE";
  for (let page = 0; page < settings.maxPages; page++) {
    let result: LiveOsvPage;
    try {
      result = await fetchPage(request, next, options.fetchImpl ?? fetch, settings);
    } catch (cause) {
      status = "UPSTREAM_ERROR";
      warnings.push("OSV request failed; results may be incomplete: " +
        (cause instanceof Error ? cause.message : "Unknown upstream failure."));
      break;
    }
    queriedPages++;
    responseBytes += result.responseBytes;
    for (const reference of result.references) {
      if (all.size >= settings.maxRecords && !all.has(reference.id)) {
        status = "TRUNCATED";
        warnings.push("OSV record budget exceeded; later results were excluded.");
        break;
      }
      const older = all.get(reference.id);
      if (older && older.fingerprint !== reference.fingerprint) {
        status = "UPSTREAM_ERROR";
        warnings.push("OSV returned contradictory records across pages.");
        break;
      }
      all.set(reference.id, reference);
    }
    if (status !== "COMPLETE") break;
    if (!result.nextPageToken) break;
    if (fetchedTokens.has(result.nextPageToken)) {
      status = "UPSTREAM_ERROR";
      warnings.push("OSV repeated a pagination token.");
      break;
    }
    fetchedTokens.add(result.nextPageToken);
    next = result.nextPageToken;
    if (page === settings.maxPages - 1) {
      status = "TRUNCATED";
      warnings.push("OSV returned more pages than the query budget permits.");
    }
  }
  const vulnerabilities = [...all.values()].sort((a, b) =>
    a.id.localeCompare(b.id));
  const canonical = {
    schema: "cyberpilot.assets.osv.live.query.v1" as const,
    endpoint: OSV_API_ORIGIN,
    package: request,
    checkedAt, provider: "OSV_DEV_API" as const,
    transport: "HTTPS_FIXED_ENDPOINT" as const,
    status, queriedPages, responseBytes, vulnerabilities,
    providerReportedCount: vulnerabilities.length,
    exactEnumeratedCount: vulnerabilities.filter(v =>
      v.exactVersionListed && v.packageIdentityListed &&
      v.withdrawn === null).length,
    nonEnumeratedCount: vulnerabilities.filter(v =>
      !v.exactVersionListed || !v.packageIdentityListed).length,
    withdrawnCount: vulnerabilities.filter(v =>
      v.withdrawn !== null).length,
    warnings,
  };
  return { ...canonical, digest: digest(canonical) };
}
