import { createHash, timingSafeEqual } from "node:crypto";

export type GoogleEvidenceState =
  "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type GoogleCapability =
  "DIRECTORY_USERS" | "DIRECTORY_DOMAINS" |
  "DIRECTORY_ORGANIZATION_UNITS" | "REPORTS_LOGIN" |
  "REPORTS_ADMIN" | "USER_MFA_ATTRIBUTES";
export type GoogleEntitlement =
  "AVAILABLE" | "REQUIRES_PERMISSION" | "NOT_AVAILABLE" | "UNKNOWN";
export type GoogleAuditClass =
  "LOGIN" | "ADMIN" | "UNKNOWN";
export type GoogleFindingSeverity =
  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "UNKNOWN";
export type GoogleSourceType =
  "GOOGLE_DIRECTORY" | "GOOGLE_REPORTS" | "SYNTHETIC_FIXTURE";
export type GoogleEvidenceRecord = {
  schema: "cyberpilot.google.evidence.v1";
  organizationId: string;
  provider: "GOOGLE_WORKSPACE";
  capability: GoogleCapability;
  controlId: string;
  scope: string;
  subjectHash: string;
  state: GoogleEvidenceState;
  checkedAt: string;
  observedAt: string | null;
  confidence: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
  sourceType: GoogleSourceType;
  sourceReference: string;
  providerResponseDigest: string | null;
  details: Record<string, boolean | number | string | null>;
  declaredNotObserved: boolean;
  licenseCoverageUnknown: boolean;
  permissionsComplete: boolean;
  externalLiveVerified: false;
  customerOperationalApproval: false;
};
export type DirectoryUser = {
  id: string;
  primaryEmail: string;
  suspended: boolean | null;
  isAdmin: boolean | null;
  isDelegatedAdmin: boolean | null;
  isEnrolledIn2Sv: boolean | null;
  isEnforcedIn2Sv: boolean | null;
  lastLoginTime: string | null;
  creationTime: string | null;
  orgUnitPath: string | null;
  aliases: string[];
  recoveryDataPresent: boolean | null;
  rawFieldCoverage: string[];
  unsupportedFields: string[];
};
export type DirectoryDomain = {
  domainName: string;
  isPrimary: boolean | null;
  verified: boolean | null;
  source: "DIRECTORY";
};
export type DirectoryOrgUnit = {
  orgUnitId: string;
  name: string;
  orgUnitPath: string;
  parentOrgUnitPath: string | null;
  blockInheritance: boolean | null;
};
export type ReportsEvent = {
  eventId: string;
  eventTime: string;
  actorHash: string | null;
  eventName: string;
  category: GoogleAuditClass;
  parameters: Array<{ name: string; value: string | null }>;
  ipAddressStored: false;
  rawActorEmailStored: false;
  source: "GOOGLE_REPORTS";
};
export type GoogleDirectoryObservation = {
  schema: "cyberpilot.google.directory.observation.v1";
  organizationId: string;
  generatedAt: string;
  source: "SYNTHETIC_FIXTURE" | "GOOGLE_DIRECTORY";
  users: DirectoryUser[];
  domains: DirectoryDomain[];
  orgUnits: DirectoryOrgUnit[];
  reports: ReportsEvent[];
  coverage: Record<GoogleCapability, GoogleEntitlement>;
  failures: Array<{
    capability: GoogleCapability;
    category: "PERMISSION" | "QUOTA" | "TRANSPORT" |
      "MALFORMED" | "PARTIAL" | "UNAVAILABLE";
    explanation: string;
    recoverable: boolean;
  }>;
  truncation: Record<GoogleCapability, boolean>;
  unknownCapabilities: GoogleCapability[];
  digest: string;
  liveProviderVerified: false;
  fullTenantCoverageClaimed: false;
  securityCertified: false;
};
export const CAPABILITIES: readonly GoogleCapability[] = [
  "DIRECTORY_USERS", "DIRECTORY_DOMAINS",
  "DIRECTORY_ORGANIZATION_UNITS", "REPORTS_LOGIN",
  "REPORTS_ADMIN", "USER_MFA_ATTRIBUTES",
] as const;
const MAX_USERS = 3000, MAX_DOMAINS = 300, MAX_OUS = 500;
const MAX_EVENTS = 3000, MAX_ALIASES = 40;
const SUSPICIOUS = /[\u0000-\u001f\u007f]/;
export class GoogleContractError extends Error {
  constructor(
    public readonly code: "INVALID" | "LIMIT" | "CONFLICT",
    message: string,
  ) { super(message); this.name = "GoogleContractError"; }
}
function invalid(message: string): never {
  throw new GoogleContractError("INVALID", message);
}
export function record(input: unknown, label: string) {
  if (!input || typeof input !== "object" ||
      Array.isArray(input))
    invalid("Invalid Google " + label + " object.");
  return input as Record<string, unknown>;
}
export function boundedString(value: unknown, label: string,
  maximum = 250) {
  if (typeof value !== "string" || !value.trim() ||
      value.length > maximum || SUSPICIOUS.test(value))
    invalid("Invalid Google " + label + ".");
  return value.trim();
}
export function optionalString(value: unknown, label: string,
  maximum = 250) {
  if (value === null || value === undefined || value === "") return null;
  return boundedString(value, label, maximum);
}
export function optionalBool(value: unknown, label: string) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "boolean") invalid("Invalid Google " + label + ".");
  return value;
}
export function utcDate(value: unknown, label: string) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value))
    invalid("Invalid Google UTC " + label + ".");
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()))
    invalid("Unparseable Google UTC " + label + ".");
  return date.toISOString();
}
export function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function equalDigest(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
export function subjectHash(organizationId: string, subject: string) {
  const organization = boundedString(organizationId, "organization ID", 128);
  const normalized = boundedString(subject, "subject", 320)
    .toLowerCase();
  return createHash("sha256").update(organization).update("\0")
    .update(normalized).digest("hex");
}
export function normalizeUser(raw: unknown): DirectoryUser {
  const v = record(raw, "user");
  const id = boundedString(v.id, "user ID", 256);
  const primaryEmail = boundedString(v.primaryEmail,
    "primary email", 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(primaryEmail))
    invalid("Malformed Google primary email.");
  if (v.aliases !== undefined && !Array.isArray(v.aliases))
    invalid("Invalid Google aliases.");
  const aliases = (v.aliases ?? [] as unknown[])
    .map(alias => boundedString(alias, "alias", 320).toLowerCase());
  if (aliases.length > MAX_ALIASES ||
      new Set(aliases).size !== aliases.length)
    invalid("Google aliases exceed limits or are duplicated.");
  const expectedFields = [
    "id", "primaryEmail", "suspended", "isAdmin",
    "isDelegatedAdmin", "isEnrolledIn2Sv", "isEnforcedIn2Sv",
    "lastLoginTime", "creationTime", "orgUnitPath", "aliases",
    "recoveryEmail", "recoveryPhone",
  ];
  const observedFields = expectedFields.filter(key =>
    v[key] !== undefined && v[key] !== null);
  return {
    id, primaryEmail,
    suspended: optionalBool(v.suspended, "suspended"),
    isAdmin: optionalBool(v.isAdmin, "superadmin"),
    isDelegatedAdmin: optionalBool(v.isDelegatedAdmin, "delegated admin"),
    isEnrolledIn2Sv: optionalBool(v.isEnrolledIn2Sv, "2SV enrollment"),
    isEnforcedIn2Sv: optionalBool(v.isEnforcedIn2Sv, "2SV enforcement"),
    lastLoginTime: utcDate(v.lastLoginTime, "last login"),
    creationTime: utcDate(v.creationTime, "creation date"),
    orgUnitPath: optionalString(v.orgUnitPath, "org unit", 300),
    aliases, recoveryDataPresent:
      v.recoveryEmail !== undefined || v.recoveryPhone !== undefined ?
        !!v.recoveryEmail || !!v.recoveryPhone : null,
    rawFieldCoverage: observedFields,
    unsupportedFields: Object.keys(v).filter(key =>
      !expectedFields.includes(key)).slice(0, 30),
  };
}
export function normalizeDomain(raw: unknown): DirectoryDomain {
  const v = record(raw, "domain");
  const domainName = boundedString(v.domainName, "domain", 253)
    .toLowerCase();
  if (!/^[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(domainName) ||
      !domainName.includes(".") || domainName.includes(".."))
    invalid("Invalid Google domain name.");
  return {
    domainName,
    isPrimary: optionalBool(v.isPrimary, "primary domain"),
    verified: optionalBool(v.verified, "domain verified"),
    source: "DIRECTORY",
  };
}
export function normalizeOrgUnit(raw: unknown): DirectoryOrgUnit {
  const v = record(raw, "organization unit");
  const path = boundedString(v.orgUnitPath, "OU path", 512);
  if (!path.startsWith("/") || path.includes(".."))
    invalid("Invalid Google OU path.");
  const parent = optionalString(v.parentOrgUnitPath,
    "parent OU path", 512);
  if (parent && !parent.startsWith("/"))
    invalid("Invalid Google OU parent path.");
  return {
    orgUnitId: boundedString(v.orgUnitId, "OU ID", 256),
    name: boundedString(v.name, "OU name", 150),
    orgUnitPath: path, parentOrgUnitPath: parent,
    blockInheritance: optionalBool(v.blockInheritance, "inheritance"),
  };
}
function parseEventParameters(input: unknown) {
  if (input === undefined || input === null) return [];
  if (!Array.isArray(input) || input.length > 40)
    invalid("Invalid Google audit event parameters.");
  return input.map(item => {
    const v = record(item, "event parameter");
    const name = boundedString(v.name, "parameter name", 100);
    const value = v.value ?? v.intValue ?? v.boolValue;
    return {
      name,
      value: value === null || value === undefined ? null :
        typeof value === "boolean" || typeof value === "number" ?
          String(value) :
          boundedString(value, "event parameter", 300),
    };
  }).filter(item => !/password|token|secret|credential|ip.?address|email/i
    .test(item.name));
}
export function normalizeReportEvent(raw: unknown,
  organizationId: string, category: GoogleAuditClass): ReportsEvent {
  const v = record(raw, "report");
  const id = record(v.id, "report event ID");
  const events = v.events;
  if (!Array.isArray(events) || events.length !== 1)
    invalid("Expected exactly one normalized report event.");
  const event = record(events[0], "report event");
  const actor = v.actor === undefined ? null : record(v.actor, "report actor");
  const actorEmail = actor?.email;
  return {
    eventId: boundedString(id.uniqueQualifier ??
      id.applicationName + ":" + id.time, "report identifier", 250),
    eventTime: utcDate(id.time, "report timestamp") ??
      invalid("Report timestamp required."),
    actorHash: typeof actorEmail === "string" ?
      subjectHash(organizationId, actorEmail) : null,
    eventName: boundedString(event.name, "report event name", 200),
    category, parameters: parseEventParameters(event.parameters),
    ipAddressStored: false, rawActorEmailStored: false,
    source: "GOOGLE_REPORTS",
  };
}
export function extractReportEvents(raw: unknown,
  organizationId: string, category: GoogleAuditClass): ReportsEvent[] {
  const v = record(raw, "report item");
  if (!Array.isArray(v.events) || v.events.length > 50)
    invalid("Report item requires bounded events array.");
  return v.events.map((item, i) => normalizeReportEvent({
    id: { ...record(v.id, "report ID"),
      uniqueQualifier: boundedString(
        record(v.id, "report ID").uniqueQualifier ??
        record(v.id, "report ID").time, "qualifier", 200) + ":" + i },
    actor: v.actor, events: [item],
  }, organizationId, category));
}
export function normalizeBatch(input: {
  organizationId: string;
  checkedAt: string;
  source: "SYNTHETIC_FIXTURE" | "GOOGLE_DIRECTORY";
  users?: unknown[]; domains?: unknown[];
  orgUnits?: unknown[]; reports?: ReportsEvent[];
  coverage?: Partial<Record<GoogleCapability, GoogleEntitlement>>;
  failures?: GoogleDirectoryObservation["failures"];
  truncation?: Partial<Record<GoogleCapability, boolean>>;
}): GoogleDirectoryObservation {
  const organizationId = boundedString(input.organizationId,
    "organization ID", 128);
  const timestamp = utcDate(input.checkedAt, "inspection clock");
  if (!timestamp) invalid("Inspection clock required.");
  if (input.source !== "SYNTHETIC_FIXTURE" &&
      input.source !== "GOOGLE_DIRECTORY")
    invalid("Untrusted observation source.");
  const users = input.users ?? [], domains = input.domains ?? [];
  const ous = input.orgUnits ?? [], reports = input.reports ?? [];
  if (!Array.isArray(users) || users.length > MAX_USERS ||
      !Array.isArray(domains) || domains.length > MAX_DOMAINS ||
      !Array.isArray(ous) || ous.length > MAX_OUS ||
      !Array.isArray(reports) || reports.length > MAX_EVENTS)
    throw new GoogleContractError("LIMIT",
      "Google observation exceeded safe row limits.");
  const normalizedUsers = users.map(normalizeUser);
  const normalizedDomains = domains.map(normalizeDomain);
  const normalizedOus = ous.map(normalizeOrgUnit);
  for (const [type, values] of [
    ["users", normalizedUsers.map(x => x.id)],
    ["emails", normalizedUsers.map(x => x.primaryEmail)],
    ["domains", normalizedDomains.map(x => x.domainName)],
    ["orgunits", normalizedOus.map(x => x.orgUnitId)],
    ["reports", reports.map(x => x.eventId)],
  ] as const) {
    if (new Set(values).size !== values.length)
      throw new GoogleContractError("CONFLICT",
        "Duplicate " + type + " in Google evidence.");
  }
  const coverage = Object.fromEntries(CAPABILITIES.map(capability =>
    [capability, input.coverage?.[capability] ?? "UNKNOWN"])) as
    Record<GoogleCapability, GoogleEntitlement>;
  if (Object.values(coverage).some(x => ![
    "AVAILABLE", "REQUIRES_PERMISSION",
    "NOT_AVAILABLE", "UNKNOWN",
  ].includes(x))) invalid("Invalid Google capability coverage.");
  const truncation = Object.fromEntries(CAPABILITIES.map(capability =>
    [capability, input.truncation?.[capability] === true])) as
    Record<GoogleCapability, boolean>;
  const failures = input.failures ?? [];
  if (!Array.isArray(failures) || failures.length > 100 ||
      failures.some(f => !CAPABILITIES.includes(f.capability) ||
        !["PERMISSION", "QUOTA", "TRANSPORT", "MALFORMED",
          "PARTIAL", "UNAVAILABLE"].includes(f.category)))
    invalid("Invalid partial error catalog.");
  const unknownCapabilities = CAPABILITIES.filter(capability =>
    coverage[capability] !== "AVAILABLE" || truncation[capability] ||
    failures.some(f => f.capability === capability));
  const canonical = {
    schema: "cyberpilot.google.directory.observation.v1" as const,
    organizationId, generatedAt: timestamp, source: input.source,
    users: normalizedUsers, domains: normalizedDomains,
    orgUnits: normalizedOus, reports,
    coverage, failures, truncation, unknownCapabilities,
    liveProviderVerified: false as const,
    fullTenantCoverageClaimed: false as const,
    securityCertified: false as const,
  };
  return { ...canonical, digest: digest(canonical) };
}
export function verifyObservation(observation: GoogleDirectoryObservation) {
  const { digest: fingerprint, ...canonical } = observation;
  const issues: string[] = [];
  if (!equalDigest(fingerprint, digest(canonical)))
    issues.push("Google observation content changed.");
  if (observation.liveProviderVerified ||
      observation.fullTenantCoverageClaimed ||
      observation.securityCertified)
    issues.push("External claim unsupported.");
  if (observation.unknownCapabilities.some(capability =>
    observation.coverage[capability] === "AVAILABLE" &&
    !observation.truncation[capability] &&
    !observation.failures.some(f => f.capability === capability)))
    issues.push("Incorrect unknown capability.");
  if (observation.users.length > MAX_USERS ||
      observation.reports.length > MAX_EVENTS)
    issues.push("Observation size out of bounds.");
  return { valid: issues.length === 0, issues };
}
export function buildEvidenceRecords(
  observation: GoogleDirectoryObservation,
): GoogleEvidenceRecord[] {
  if (!verifyObservation(observation).valid)
    throw new GoogleContractError("CONFLICT",
      "Cannot export corrupted Google observations.");
  const out: GoogleEvidenceRecord[] = [];
  const base = (capability: GoogleCapability, controlId: string,
    subject: string, state: GoogleEvidenceState,
    details: GoogleEvidenceRecord["details"]): GoogleEvidenceRecord => ({
    schema: "cyberpilot.google.evidence.v1",
    organizationId: observation.organizationId,
    provider: "GOOGLE_WORKSPACE", capability,
    controlId, scope: capability === "DIRECTORY_USERS" ?
      "IDENTITIES" : "TENANT",
    subjectHash: subjectHash(observation.organizationId, subject),
    state, checkedAt: observation.generatedAt,
    observedAt: state === "OBSERVED" ? observation.generatedAt : null,
    confidence: state === "OBSERVED" ? "MEDIUM" : "UNKNOWN",
    sourceType: observation.source === "SYNTHETIC_FIXTURE" ?
      "SYNTHETIC_FIXTURE" : capability.startsWith("REPORTS") ?
        "GOOGLE_REPORTS" : "GOOGLE_DIRECTORY",
    sourceReference: observation.digest,
    providerResponseDigest: observation.digest,
    details, declaredNotObserved: state === "DECLARED",
    licenseCoverageUnknown: observation.coverage[capability] === "UNKNOWN",
    permissionsComplete:
      observation.coverage[capability] === "AVAILABLE" &&
      !observation.truncation[capability],
    externalLiveVerified: false,
    customerOperationalApproval: false,
  });
  for (const user of observation.users) {
    const subject = user.id;
    out.push(base("DIRECTORY_USERS", "GOOGLE_USER_SUSPENDED",
      subject, user.suspended === null ? "UNKNOWN" : "OBSERVED",
      { suspended: user.suspended, lastLoginKnown: !!user.lastLoginTime }));
    out.push(base("DIRECTORY_USERS", "GOOGLE_ADMIN_PRIVILEGE",
      subject, user.isAdmin === null ? "UNKNOWN" : "OBSERVED",
      { isAdmin: user.isAdmin, isDelegatedAdmin: user.isDelegatedAdmin }));
    out.push(base("USER_MFA_ATTRIBUTES", "GOOGLE_USER_2SV",
      subject,
      observation.coverage.USER_MFA_ATTRIBUTES !== "AVAILABLE" ||
      user.isEnrolledIn2Sv === null ? "UNKNOWN" : "OBSERVED",
      { enrolled: user.isEnrolledIn2Sv,
        enforced: user.isEnforcedIn2Sv, sourceCompleteness: user.rawFieldCoverage.length }));
  }
  for (const domain of observation.domains)
    out.push(base("DIRECTORY_DOMAINS", "GOOGLE_DOMAIN_VERIFICATION",
      domain.domainName,
      domain.verified === null ? "UNKNOWN" : "OBSERVED",
      { verified: domain.verified, isPrimary: domain.isPrimary }));
  for (const capability of CAPABILITIES) {
    if (observation.coverage[capability] === "AVAILABLE" &&
        !observation.truncation[capability] &&
        !observation.failures.some(f => f.capability === capability))
      continue;
    out.push(base(capability, "GOOGLE_PROVIDER_COVERAGE",
      capability, observation.failures.some(f => f.capability === capability &&
        f.category !== "PARTIAL") ? "ERROR" : "UNKNOWN",
      { coverage: observation.coverage[capability],
        truncated: observation.truncation[capability],
        failureCount: observation.failures.filter(f =>
          f.capability === capability).length }));
  }
  return out;
}
export function summarizeCoverage(observation: GoogleDirectoryObservation) {
  if (!verifyObservation(observation).valid)
    throw new GoogleContractError("CONFLICT", "Observation is invalid.");
  const all = CAPABILITIES.map(capability => ({
    capability, entitlement: observation.coverage[capability],
    truncated: observation.truncation[capability],
    failures: observation.failures.filter(f => f.capability === capability),
    reliableForAssessment:
      observation.coverage[capability] === "AVAILABLE" &&
      !observation.truncation[capability] &&
      !observation.failures.some(f => f.capability === capability),
  }));
  return {
    capabilities: all,
    completeCapabilities: all.filter(x => x.reliableForAssessment).length,
    totalCapabilities: all.length,
    coveragePercent: Math.round(
      100 * all.filter(x => x.reliableForAssessment).length / all.length),
    partial: all.some(x => !x.reliableForAssessment),
    tenantSecurityProven: false as const,
    actualProviderValidated: false as const,
  };
}
