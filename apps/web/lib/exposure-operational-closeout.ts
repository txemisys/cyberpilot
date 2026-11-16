import { createHash } from "node:crypto";

/**
 * Independent technical preflight for persisted Exposure authorizations,
 * schedules and quota reservations. Read only, organization scoped.
 * No operator UI or audit report can enable a LIVE collector by itself.
 */
export type ExposureCloseoutAuthorization = {
  id: string; organizationId: string; domain: string;
  revision: number; state: string; method: string;
  challengeExpiresAt: string; verifiedAt: string | null;
  revokedAt: string | null; evidenceDigest: string | null;
  updatedAt: string;
};
export type ExposureCloseoutAuthorizationEvent = {
  id: string; organizationId: string;
  authorizationId: string; revision: number;
  action: string; priorState: string; newState: string;
  actorUserId: string; createdAt: string;
};
export type ExposureCloseoutSchedule = {
  id: string; organizationId: string;
  authorizationId: string; domain: string;
  revision: number; state: string;
  sources: string[];
  policyDigest: string;
  legalConsentVerified: boolean;
  dailyDnsLimit: number; dailyTlsLimit: number;
  dailyHttpLimit: number;
  minimumIntervalMs: number;
  lastAttemptAt: string | null;
  nextEligibleAt: string | null;
  updatedAt: string;
};
export type ExposureCloseoutScheduleEvent = {
  id: string; organizationId: string;
  scheduleId: string; revision: number;
  action: string; priorState: string; currentState: string;
  actorUserId: string; createdAt: string;
};
export type ExposureCloseoutReservation = {
  id: string; organizationId: string;
  scheduleId: string; requestId: string;
  authorizationRevision: number;
  status: string;
  requestedSources: string[];
  reservedDns: number; reservedTls: number; reservedHttp: number;
  actualDns: number; actualTls: number; actualHttp: number;
  periodStart: string;
  leaseExpiresAt: string;
  finishedAt: string | null;
  rejectionCode: string | null;
  evidenceDigest: string | null;
  createdAt: string;
};
export type ExposureCloseoutInput = {
  organizationId: string;
  generatedAt: string;
  authorizations: ExposureCloseoutAuthorization[];
  authorizationEvents: ExposureCloseoutAuthorizationEvent[];
  schedules: ExposureCloseoutSchedule[];
  scheduleEvents: ExposureCloseoutScheduleEvent[];
  reservations: ExposureCloseoutReservation[];
  collectionCounts: {
    authorizations: number;
    authorizationEvents: number;
    schedules: number;
    scheduleEvents: number;
    reservations: number;
  };
  collectionCaps: {
    authorizations: number;
    authorizationEvents: number;
    schedules: number;
    scheduleEvents: number;
    reservations: number;
  };
};
export type ExposureCloseoutGate = {
  id: string;
  severity: "BLOCK" | "ADVISORY" | "PASS";
  reason: string;
  expected: number; actual: number;
  relatedIds: string[];
};
export type ExposureCloseoutDomain = {
  domain: string;
  authorizationId: string | null;
  technicalOwnershipState: string;
  authorizationRevision: number | null;
  scheduleId: string | null;
  scheduleState: string | null;
  sources: string[];
  consentIndependentlyVerified: false;
  liveCollectionAllowed: false;
  networkCallsProven: 0;
  reservedSlots: number;
  deniedReservations: number;
  quotaAttempted: { dns: number; tls: number; http: number };
  quotaReportedActual: { dns: number; tls: number; http: number };
  authorizationHistoryEvents: number;
  scheduleHistoryEvents: number;
  blockers: string[];
  advisories: string[];
  nextActions: string[];
};
export type ExposureCloseoutReport = {
  schema: "cyberpilot.exposure.operational.readiness.v1";
  organizationId: string;
  generatedAt: string;
  verdict: "BLOCKED" | "REVIEW_REQUIRED";
  sourceBounded: boolean;
  allTenantScoped: boolean;
  domains: ExposureCloseoutDomain[];
  gates: ExposureCloseoutGate[];
  total: {
    authorizations: number;
    schedules: number;
    reservations: number;
    deniedReservations: number;
    enabledSchedules: number;
    verifiedDomainProofs: number;
    actualNetworkCallsReported: number;
    orphanedRows: number;
    eventSequenceAnomalies: number;
    duplicatedRequests: number;
  };
  limitations: string[];
  digest: string;
  legalCustomerConsentSigned: false;
  providerTrafficPermitted: false;
  externalInfrastructureEvaluated: false;
  priorCyberScoreChanged: false;
};
const validSources = ["DNS","TLS_HANDSHAKE","HTTPS_HEADERS"];
const validStates = ["DISABLED","PAUSED","READY","REVOKED"];
function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}
function validIso(value: string | null): boolean {
  return typeof value === "string" &&
    Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString() === value;
}
function validDigest(value: string | null): boolean {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function validDomain(domain: string): boolean {
  return typeof domain === "string" &&
    domain.length >= 4 && domain.length <= 253 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(domain) &&
    domain.includes(".") && !domain.includes("..");
}
function validId(value: string): boolean {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function canonical(value: unknown): string {
  if (value === null || typeof value !== "object")
    return JSON.stringify(value);
  if (Array.isArray(value))
    return "[" + value.map(canonical).join(",") + "]";
  return "{" + Object.entries(value)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, field]) => JSON.stringify(key) + ":" +
      canonical(field)).join(",") + "}";
}
function digest(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}
function countBy<T>(rows: T[], id: (row: T) => string) {
  const result = new Map<string, T[]>();
  for (const row of rows) {
    const key = id(row);
    result.set(key, [...(result.get(key) ?? []), row]);
  }
  return result;
}
function contiguous(values: number[], revision: number): boolean {
  return Number.isSafeInteger(revision) && revision >= 1 &&
    values.length === revision &&
    [...values].sort((a, b) => a - b)
      .every((x, i) => x === i + 1);
}
function gate(
  id: string, severity: ExposureCloseoutGate["severity"],
  reason: string, expected: number, actual: number,
  relatedIds: string[] = [],
): ExposureCloseoutGate {
  return {
    id, severity, reason, expected, actual,
    relatedIds: unique(relatedIds).sort().slice(0, 200),
  };
}
function bounded(input: ExposureCloseoutInput): boolean {
  return Object.entries(input.collectionCounts).every(([key, value]) =>
    Number.isSafeInteger(value) && value >= 0 &&
    value <= input.collectionCaps[
      key as keyof ExposureCloseoutInput["collectionCaps"]
    ]);
}
function matchingTenant(input: ExposureCloseoutInput): string[] {
  const mismatches: string[] = [];
  for (const [label, rows] of [
    ["authorization", input.authorizations],
    ["authorization-event", input.authorizationEvents],
    ["schedule", input.schedules],
    ["schedule-event", input.scheduleEvents],
    ["reservation", input.reservations],
  ] as const) {
    for (const row of rows)
      if (row.organizationId !== input.organizationId ||
          !validId(row.id))
        mismatches.push(label + ":" + String(row.id).slice(0, 80));
  }
  return mismatches;
}
const recommended: Record<string, string> = {
  AUTHORIZATION_MISSING: "Register and validate technical domain ownership.",
  DOMAIN_PROOF_INCOMPLETE: "Refresh or reverify the DNS ownership challenge.",
  DOMAIN_PROOF_REVOKED: "Obtain a new authorized ownership proof.",
  SCHEDULE_MISSING: "Define an opt-in passive collection schedule.",
  SCHEDULE_DISABLED: "Review the disabled policy without enabling LIVE traffic.",
  CONSENT_NOT_INDEPENDENTLY_ATTESTED:
    "Use a separately authenticated legal-consent verification service.",
  TRUSTED_WORKER_UNAVAILABLE:
    "Deploy and verify a network-isolated collector before any external requests.",
  QUOTA_EXCEEDED:
    "Review tenant budget and reservation provenance; do not bypass limits.",
  AUDIT_SEQUENCE_INCOMPLETE:
    "Investigate missing immutable PostgreSQL audit events.",
  RESERVATION_ANOMALY:
    "Investigate reservation lineage, concurrency and quota accounting.",
};
export function buildExposureOperationalCloseout(
  input: ExposureCloseoutInput,
): ExposureCloseoutReport {
  if (!validId(input.organizationId) ||
      !validIso(input.generatedAt))
    throw Error("Invalid Exposure closeout organization or time.");
  const gates: ExposureCloseoutGate[] = [];
  const mismatches = matchingTenant(input);
  const scoped = mismatches.length === 0;
  gates.push(gate("TENANT_SCOPE",
    scoped ? "PASS" : "BLOCK",
    "All source rows must be owned by the requested tenant.",
    0, mismatches.length, mismatches));
  const sourceBounded = bounded(input);
  gates.push(gate("BOUNDED_DATABASE_READ",
    sourceBounded ? "PASS" : "BLOCK",
    "No incomplete bounded query may be presented as a complete assessment.",
    0, sourceBounded ? 0 : 1));
  const authById = new Map(input.authorizations.map(a => [a.id, a]));
  const scheduleById = new Map(input.schedules.map(s => [s.id, s]));
  const authEventsById = countBy(input.authorizationEvents,
    event => event.authorizationId);
  const scheduleEventsById = countBy(input.scheduleEvents,
    event => event.scheduleId);
  const reservationBySchedule = countBy(input.reservations,
    reservation => reservation.scheduleId);
  const orphanAuthEvents = input.authorizationEvents.filter(e =>
    !authById.has(e.authorizationId));
  const orphanScheduleEvents = input.scheduleEvents.filter(e =>
    !scheduleById.has(e.scheduleId));
  const orphanReservations = input.reservations.filter(r =>
    !scheduleById.has(r.scheduleId));
  const orphanSchedules = input.schedules.filter(s =>
    !authById.has(s.authorizationId));
  const orphanedRows = orphanAuthEvents.length +
    orphanScheduleEvents.length +
    orphanReservations.length + orphanSchedules.length;
  gates.push(gate("FOREIGN_KEY_PROVENANCE",
    orphanedRows === 0 ? "PASS" : "BLOCK",
    "All events, schedules and reservations need scoped parent records.",
    0, orphanedRows,
    [...orphanAuthEvents, ...orphanScheduleEvents,
      ...orphanReservations, ...orphanSchedules].map(x => x.id)));
  const invalidAuthorization = input.authorizations.filter(a =>
    !validDomain(a.domain) ||
    !["PENDING","VERIFIED","EXPIRED","REVOKED"].includes(a.state) ||
    !["DNS_TOKEN","HTTP_TOKEN"].includes(a.method) ||
    !validIso(a.challengeExpiresAt) ||
    a.verifiedAt !== null && !validIso(a.verifiedAt) ||
    a.revokedAt !== null && !validIso(a.revokedAt) ||
    a.evidenceDigest !== null && !validDigest(a.evidenceDigest));
  gates.push(gate("AUTHORIZATION_RECORDS",
    invalidAuthorization.length ? "BLOCK" : "PASS",
    "Ownership evidence must have canonical domain, method and dates.",
    input.authorizations.length,
    input.authorizations.length - invalidAuthorization.length,
    invalidAuthorization.map(x => x.id)));
  const invalidSchedule = input.schedules.filter(s =>
    !validDomain(s.domain) ||
    !validStates.includes(s.state) ||
    !validDigest(s.policyDigest) ||
    s.sources.length === 0 ||
    s.sources.length > 3 ||
    s.sources.length !== unique(s.sources).length ||
    s.sources.some(x => !validSources.includes(x)) ||
    !Number.isSafeInteger(s.revision) || s.revision < 1 ||
    !Number.isSafeInteger(s.dailyDnsLimit) ||
    !Number.isSafeInteger(s.dailyTlsLimit) ||
    !Number.isSafeInteger(s.dailyHttpLimit) ||
    s.dailyDnsLimit < 0 || s.dailyDnsLimit > 8 ||
    s.dailyTlsLimit < 0 || s.dailyTlsLimit > 1 ||
    s.dailyHttpLimit < 0 || s.dailyHttpLimit > 1);
  gates.push(gate("SCHEDULE_POLICY_INTEGRITY",
    invalidSchedule.length ? "BLOCK" : "PASS",
    "Schedules must preserve allowed sources, ceilings and digests.",
    input.schedules.length,
    input.schedules.length - invalidSchedule.length,
    invalidSchedule.map(x => x.id)));
  const unboundSchedule = input.schedules.filter(s => {
    const auth = authById.get(s.authorizationId);
    return !auth || auth.domain !== s.domain;
  });
  gates.push(gate("SCHEDULE_AUTHORIZATION_BINDING",
    unboundSchedule.length ? "BLOCK" : "PASS",
    "Schedules must bind the exact authorized domain.",
    input.schedules.length,
    input.schedules.length - unboundSchedule.length,
    unboundSchedule.map(x => x.id)));
  const authBroken = input.authorizations.filter(a => {
    const events = authEventsById.get(a.id) ?? [];
    if (!contiguous(events.map(x => x.revision), a.revision))
      return true;
    const latest = [...events].sort((x, y) =>
      y.revision - x.revision)[0];
    return !latest || latest.newState !== a.state ||
      !events.every(e => validIso(e.createdAt) &&
        validId(e.actorUserId));
  });
  gates.push(gate("DOMAIN_OWNERSHIP_CAS_AUDIT",
    authBroken.length ? "BLOCK" : "PASS",
    "Every domain authorization revision needs an immutable audit event.",
    input.authorizations.length,
    input.authorizations.length - authBroken.length,
    authBroken.map(x => x.id)));
  const scheduleBroken = input.schedules.filter(s => {
    const events = scheduleEventsById.get(s.id) ?? [];
    if (!contiguous(events.map(x => x.revision), s.revision))
      return true;
    const latest = [...events].sort((x, y) =>
      y.revision - x.revision)[0];
    return !latest || latest.currentState !== s.state ||
      !events.every(e => validIso(e.createdAt) &&
        validId(e.actorUserId));
  });
  gates.push(gate("SCHEDULE_CAS_AUDIT",
    scheduleBroken.length ? "BLOCK" : "PASS",
    "The persistent schedule history must be complete and ordered.",
    input.schedules.length,
    input.schedules.length - scheduleBroken.length,
    scheduleBroken.map(x => x.id)));
  const requestIds = input.reservations.map(x => x.requestId);
  const duplicateIds = requestIds.filter((x, index) =>
    requestIds.indexOf(x) !== index);
  gates.push(gate("RESERVATION_IDEMPOTENCY",
    duplicateIds.length ? "BLOCK" : "PASS",
    "At most one durable reservation may exist per tenant request ID.",
    0, duplicateIds.length, duplicateIds));
  const incorrectReservations = input.reservations.filter(r => {
    const schedule = scheduleById.get(r.scheduleId);
    const auth = schedule ? authById.get(schedule.authorizationId) : null;
    const total = r.reservedDns + r.reservedTls + r.reservedHttp;
    const actual = r.actualDns + r.actualTls + r.actualHttp;
    return !validId(r.requestId) || !schedule || !auth ||
      r.authorizationRevision > auth.revision ||
      !["DENIED","RESERVED","COMPLETE","FAILED"].includes(r.status) ||
      !validIso(r.periodStart) || !validIso(r.leaseExpiresAt) ||
      !Number.isSafeInteger(total) || total < 0 || total > 10 ||
      !Number.isSafeInteger(actual) || actual < 0 ||
      actual > total ||
      r.actualDns > r.reservedDns ||
      r.actualTls > r.reservedTls ||
      r.actualHttp > r.reservedHttp ||
      r.status === "DENIED" &&
        (total !== 0 || actual !== 0) ||
      r.status !== "DENIED" && r.rejectionCode !== null ||
      r.evidenceDigest !== null && !validDigest(r.evidenceDigest);
  });
  gates.push(gate("QUOTA_LEDGER_INTEGRITY",
    incorrectReservations.length ? "BLOCK" : "PASS",
    "Reservation status, source counts and revisions must agree.",
    input.reservations.length,
    input.reservations.length - incorrectReservations.length,
    incorrectReservations.map(x => x.id)));
  const externallyClaimsTraffic = input.reservations.filter(x =>
    x.actualDns + x.actualTls + x.actualHttp > 0);
  gates.push(gate("NO_UNVERIFIED_LIVE_COLLECTION",
    externallyClaimsTraffic.length ? "BLOCK" : "PASS",
    "No recorded actual traffic is accepted without independently verified collector evidence.",
    0, externallyClaimsTraffic.length,
    externallyClaimsTraffic.map(x => x.id)));
  const enabledWithoutIndependentConsent = input.schedules.filter(s =>
    s.state === "READY" || s.legalConsentVerified);
  gates.push(gate("INDEPENDENT_CONSENT_GUARD",
    enabledWithoutIndependentConsent.length ? "BLOCK" : "PASS",
    "The development environment must remain disabled for LIVE without verified legal consent.",
    0, enabledWithoutIndependentConsent.length,
    enabledWithoutIndependentConsent.map(x => x.id)));
  const allDomains = unique([
    ...input.authorizations.map(a => a.domain),
    ...input.schedules.map(s => s.domain),
  ]).sort();
  const domains: ExposureCloseoutDomain[] = allDomains.map(domain => {
    const auth = input.authorizations.find(a => a.domain === domain);
    const schedule = input.schedules.find(s => s.domain === domain);
    const authEvents = auth ? authEventsById.get(auth.id) ?? [] : [];
    const scheduleEvents = schedule ?
      scheduleEventsById.get(schedule.id) ?? [] : [];
    const reservations = schedule ?
      reservationBySchedule.get(schedule.id) ?? [] : [];
    const blockers: string[] = [];
    const advisories: string[] = [];
    if (!auth) blockers.push("AUTHORIZATION_MISSING");
    else if (auth.state === "REVOKED")
      blockers.push("DOMAIN_PROOF_REVOKED");
    else if (auth.state !== "VERIFIED" ||
             auth.revokedAt ||
             !auth.verifiedAt ||
             auth.verifiedAt > input.generatedAt)
      blockers.push("DOMAIN_PROOF_INCOMPLETE");
    if (!schedule) blockers.push("SCHEDULE_MISSING");
    else if (schedule.state !== "READY")
      advisories.push("SCHEDULE_DISABLED");
    blockers.push("CONSENT_NOT_INDEPENDENTLY_ATTESTED");
    blockers.push("TRUSTED_WORKER_UNAVAILABLE");
    if (auth && authBroken.some(x => x.id === auth.id) ||
        schedule && scheduleBroken.some(x => x.id === schedule.id))
      blockers.push("AUDIT_SEQUENCE_INCOMPLETE");
    if (schedule && incorrectReservations.some(x =>
      x.scheduleId === schedule.id))
      blockers.push("RESERVATION_ANOMALY");
    const attempted = {
      dns: reservations.reduce((v, x) => v + x.reservedDns, 0),
      tls: reservations.reduce((v, x) => v + x.reservedTls, 0),
      http: reservations.reduce((v, x) => v + x.reservedHttp, 0),
    };
    const actual = {
      dns: reservations.reduce((v, x) => v + x.actualDns, 0),
      tls: reservations.reduce((v, x) => v + x.actualTls, 0),
      http: reservations.reduce((v, x) => v + x.actualHttp, 0),
    };
    if (schedule &&
        (attempted.dns > schedule.dailyDnsLimit ||
         attempted.tls > schedule.dailyTlsLimit ||
         attempted.http > schedule.dailyHttpLimit))
      blockers.push("QUOTA_EXCEEDED");
    return {
      domain,
      authorizationId: auth?.id ?? null,
      technicalOwnershipState: auth?.state ?? "UNKNOWN",
      authorizationRevision: auth?.revision ?? null,
      scheduleId: schedule?.id ?? null,
      scheduleState: schedule?.state ?? null,
      sources: schedule?.sources ?? [],
      consentIndependentlyVerified: false as const,
      liveCollectionAllowed: false as const,
      networkCallsProven: 0 as const,
      reservedSlots: reservations.length,
      deniedReservations: reservations.filter(x =>
        x.status === "DENIED").length,
      quotaAttempted: attempted,
      quotaReportedActual: actual,
      authorizationHistoryEvents: authEvents.length,
      scheduleHistoryEvents: scheduleEvents.length,
      blockers: unique(blockers),
      advisories: unique(advisories),
      nextActions: unique([...blockers, ...advisories].map(x =>
        recommended[x] ?? "Investigate the " + x + " condition.")),
    };
  });
  const reportWithoutDigest = {
    schema: "cyberpilot.exposure.operational.readiness.v1" as const,
    organizationId: input.organizationId,
    generatedAt: input.generatedAt,
    verdict: (gates.some(x => x.severity === "BLOCK") ||
      domains.some(x => x.blockers.length) ?
      "BLOCKED" : "REVIEW_REQUIRED") as ExposureCloseoutReport["verdict"],
    sourceBounded, allTenantScoped: scoped,
    domains, gates,
    total: {
      authorizations: input.authorizations.length,
      schedules: input.schedules.length,
      reservations: input.reservations.length,
      deniedReservations: input.reservations.filter(x =>
        x.status === "DENIED").length,
      enabledSchedules: input.schedules.filter(x =>
        x.state === "READY").length,
      verifiedDomainProofs: input.authorizations.filter(x =>
        x.state === "VERIFIED").length,
      actualNetworkCallsReported: input.reservations.reduce((v, x) =>
        v + x.actualDns + x.actualTls + x.actualHttp, 0),
      orphanedRows,
      eventSequenceAnomalies: authBroken.length + scheduleBroken.length,
      duplicatedRequests: duplicateIds.length,
    },
    limitations: [
      "A verified TXT record proves limited technical control, not legal consent.",
      "No independent consent authority is implemented or authenticated here.",
      "No LIVE worker exists in this report; zero network calls are performed.",
      "All quota counts are persisted local records, not proof of a remote scan.",
      "A SHA-256 digest is integrity evidence, not a third-party signature.",
      "No security health status, CIS certification, or remediation is inferred.",
      "Source reads are bounded and scoped to current organization membership.",
    ],
    legalCustomerConsentSigned: false as const,
    providerTrafficPermitted: false as const,
    externalInfrastructureEvaluated: false as const,
    priorCyberScoreChanged: false as const,
  };
  return {
    ...reportWithoutDigest,
    digest: digest(reportWithoutDigest),
  };
}
export function verifyExposureOperationalCloseout(
  report: ExposureCloseoutReport,
  expectedOrganizationId?: string,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const { digest: saved, ...canonical } = report;
  if (digest(canonical) !== saved)
    errors.push("CLOSEOUT_DIGEST_INVALID");
  if (expectedOrganizationId &&
      report.organizationId !== expectedOrganizationId)
    errors.push("FOREIGN_ORGANIZATION_EVIDENCE");
  if (report.legalCustomerConsentSigned !== false ||
      report.providerTrafficPermitted !== false ||
      report.externalInfrastructureEvaluated !== false ||
      report.priorCyberScoreChanged !== false)
    errors.push("UNSUPPORTED_EXTERNAL_APPROVAL");
  if (report.domains.some(x =>
    x.consentIndependentlyVerified !== false ||
    x.liveCollectionAllowed !== false ||
    x.networkCallsProven !== 0))
    errors.push("FALSE_DOMAIN_AUTHORIZATION");
  if (report.gates.length !==
      unique(report.gates.map(x => x.id)).length)
    errors.push("DUPLICATE_CLOSEOUT_GATE");
  if (report.verdict !== "BLOCKED" &&
      report.gates.some(x => x.severity === "BLOCK"))
    errors.push("UNSUPPORTED_READY_VERDICT");
  return { valid: errors.length === 0, errors };
}
export function compareExposureOperationalCloseouts(
  earlier: ExposureCloseoutReport,
  later: ExposureCloseoutReport,
) {
  if (!verifyExposureOperationalCloseout(earlier).valid ||
      !verifyExposureOperationalCloseout(later).valid ||
      earlier.organizationId !== later.organizationId ||
      earlier.generatedAt >= later.generatedAt)
    throw Error("Invalid closeout comparison or tenant.");
  const before = new Map(earlier.domains.map(x => [x.domain, x]));
  const after = new Map(later.domains.map(x => [x.domain, x]));
  return {
    organizationId: later.organizationId,
    beforeDigest: earlier.digest,
    afterDigest: later.digest,
    domainsAdded: [...after.keys()].filter(x => !before.has(x)),
    domainsAbsent: [...before.keys()].filter(x => !after.has(x)),
    additionalReservations:
      later.total.reservations - earlier.total.reservations,
    newBlockers: later.domains.flatMap(x =>
      x.blockers.filter(b => !before.get(x.domain)?.blockers.includes(b))
        .map(b => x.domain + ":" + b)),
    resolvedBlockers: earlier.domains.flatMap(x =>
      x.blockers.filter(b => !after.get(x.domain)?.blockers.includes(b))
        .map(b => x.domain + ":" + b)),
    consentAuthorityAutomaticallyValidated: false as const,
    externalCollectionAuthorized: false as const,
    securityImprovementProven: false as const,
  };
}
export function exportExposureOperationalCloseout(
  report: ExposureCloseoutReport, format: "JSON" | "CSV" | "MARKDOWN",
) {
  if (!verifyExposureOperationalCloseout(report).valid)
    throw Error("Cannot export invalid Exposure operational report.");
  const stem = "exposure-readiness-" + report.generatedAt.slice(0, 10);
  if (format === "JSON") return {
    filename: stem + ".json",
    mime: "application/json", content: JSON.stringify(report, null, 2),
  };
  if (format === "CSV") {
    const quote = (x: string | number) =>
      '"' + String(x).replaceAll('"', '""') + '"';
    const rows = [
      ["domain","authorization","schedule","reservations",
        "denied","blockers","liveAllowed"],
      ...report.domains.map(x => [
        x.domain, x.technicalOwnershipState, x.scheduleState ?? "UNKNOWN",
        x.reservedSlots, x.deniedReservations, x.blockers.join(";"), "false",
      ]),
    ];
    return {
      filename: stem + ".csv", mime: "text/csv",
      content: rows.map(row => row.map(quote).join(",")).join("\n"),
    };
  }
  if (format !== "MARKDOWN")
    throw Error("Unsupported Exposure operational report format.");
  return {
    filename: stem + ".md", mime: "text/markdown",
    content: [
      "# Exposure operational readiness",
      "",
      "Organization: " + report.organizationId,
      "Generated: " + report.generatedAt,
      "Verdict: " + report.verdict,
      "Digest: " + report.digest,
      "",
      ...report.domains.flatMap(x => [
        "## " + x.domain,
        "Technical proof: " + x.technicalOwnershipState,
        "Schedule: " + (x.scheduleState ?? "missing"),
        "Consent independently verified: NO",
        "LIVE collection authorized: NO",
        ...x.nextActions.map(a => "- " + a),
        "",
      ]),
      "## Limitations",
      ...report.limitations.map(x => "- " + x),
    ].join("\n"),
  };
}
