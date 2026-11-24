import { createHash } from "node:crypto";
import {
  verifyTimelineEvent, type TimelineEvent, type TimelineSource,
  type TimelineIntegrity,
} from "./incident-operational-timeline-domain";

/**
 * Forensic analysis of a bounded, already-scoped incident event collection.
 * These results assess local ledger consistency; they never prove provider
 * execution, external containment or independence of evidence.
 */
export type ForensicFindingCode =
  | "SCOPE_MISMATCH" | "ENTRY_INVALID" | "EVENT_REUSED"
  | "REVISION_DUPLICATE" | "REVISION_GAP" | "FIRST_REVISION_MISSING"
  | "EVENT_TIME_REGRESSION" | "CHAIN_LINK_MISMATCH"
  | "ROOT_LINK_UNEXPECTED" | "MISSING_EVENT_DIGEST"
  | "MISSING_SOURCE" | "LEDGER_INVENTORY_TRUNCATED"
  | "SNAPSHOT_REVISION_MISMATCH" | "END_DIGEST_MISMATCH"
  | "SOURCE_TIMESTAMP_IN_FUTURE" | "PROVIDER_ASSERTION_UNSUPPORTED";
export type ForensicSeverity = "CONFLICT" | "UNKNOWN" | "INCOMPLETE";
export type ForensicFinding = {
  code: ForensicFindingCode;
  severity: ForensicSeverity;
  source: TimelineSource | null;
  sourceId: string | null;
  revision: number | null;
  eventId: string | null;
  explanation: string;
};
export type ForensicLedgerExpectation = {
  source: TimelineSource;
  sourceId: string;
  expectedRevision: number;
  expectedDigest: string | null;
  inventoryComplete: boolean;
};
export type ForensicLedger = {
  source: TimelineSource;
  sourceId: string;
  firstRevision: number | null;
  lastRevision: number | null;
  expectedRevision: number | null;
  observedEvents: number;
  actorCount: number;
  eventDigestCoverage: number;
  firstAt: string | null;
  lastAt: string | null;
  rootDigest: string | null;
  tipDigest: string | null;
  status: TimelineIntegrity;
  findingCount: number;
};
export type ForensicCaseReport = {
  schema: "cyberpilot.incident.timeline.forensic-report.v1";
  organizationId: string;
  incidentId: string;
  analyzedAt: string;
  inventoryComplete: boolean;
  sourceEvents: number;
  acceptedEvents: number;
  rejectedEvents: number;
  ledgerCount: number;
  sourceCoverage: Record<TimelineSource, number>;
  integrity: TimelineIntegrity;
  ledgers: ForensicLedger[];
  findings: ForensicFinding[];
  findingsTruncated: boolean;
  digest: string;
  externalActions: 0;
  independentProviderProof: false;
};
export type ForensicCaseRequest = {
  organizationId: string;
  incidentId: string;
  analyzedAt: string;
  events: TimelineEvent[];
  expectations?: ForensicLedgerExpectation[];
  requiredSources?: TimelineSource[];
  inventoryComplete: boolean;
  maxFindings?: number;
};
const allSources: TimelineSource[] = [
  "INCIDENT", "SITUATION_REVIEW", "TABLETOP_SESSION", "ASSURANCE_HANDOFF",
];
const id = (x: unknown): x is string =>
  typeof x === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const sha = (x: unknown): x is string =>
  typeof x === "string" && /^[0-9a-f]{64}$/.test(x);
const iso = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
    new Date(x).toISOString() === x;
const fail = (code: string): never => { throw Error(code); };
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    const v = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(v).sort()
      .filter(k => v[k] !== undefined)
      .map(k => [k, canonical(v[k])]));
  }
  return value;
}
export function forensicDigest(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(canonical(value)))
    .digest("hex");
}
function ledgerKey(source: TimelineSource, sourceId: string): string {
  return source + "\u0000" + sourceId;
}
function findingSort(a: ForensicFinding, b: ForensicFinding): number {
  const rank = { CONFLICT: 0, UNKNOWN: 1, INCOMPLETE: 2 };
  return rank[a.severity] - rank[b.severity] ||
    (a.source ?? "").localeCompare(b.source ?? "") ||
    (a.sourceId ?? "").localeCompare(b.sourceId ?? "") ||
    (a.revision ?? -1) - (b.revision ?? -1) ||
    a.code.localeCompare(b.code) ||
    (a.eventId ?? "").localeCompare(b.eventId ?? "");
}
export function validateForensicRequest(req: ForensicCaseRequest): void {
  if (!req || !id(req.organizationId) || !id(req.incidentId) ||
      !iso(req.analyzedAt) || typeof req.inventoryComplete !== "boolean")
    fail("FORENSIC_CONTEXT_INVALID");
  if (!Array.isArray(req.events) || req.events.length > 25000)
    fail("FORENSIC_EVENT_LIMIT");
  if (req.maxFindings !== undefined &&
      (!Number.isSafeInteger(req.maxFindings) ||
       req.maxFindings < 1 || req.maxFindings > 5000))
    fail("FORENSIC_FINDING_LIMIT");
  if (req.events.some(e => !e || e.organizationId !== req.organizationId ||
      e.incidentId !== req.incidentId))
    fail("FORENSIC_CROSS_TENANT_OR_INCIDENT");
  if (req.requiredSources !== undefined &&
      (!Array.isArray(req.requiredSources) ||
       req.requiredSources.some(x => !allSources.includes(x)) ||
       new Set(req.requiredSources).size !== req.requiredSources.length))
    fail("FORENSIC_REQUIRED_SOURCES_INVALID");
  if (req.expectations !== undefined) {
    if (!Array.isArray(req.expectations) || req.expectations.length > 1500)
      fail("FORENSIC_EXPECTATION_LIMIT");
    const seen = new Set<string>();
    for (const row of req.expectations) {
      if (!row || !allSources.includes(row.source) || !id(row.sourceId) ||
          !Number.isSafeInteger(row.expectedRevision) ||
          row.expectedRevision < 1 || row.expectedRevision > 25000 ||
          row.expectedDigest !== null && !sha(row.expectedDigest) ||
          typeof row.inventoryComplete !== "boolean")
        fail("FORENSIC_EXPECTATION_INVALID");
      const key = ledgerKey(row.source, row.sourceId);
      if (seen.has(key)) fail("FORENSIC_EXPECTATION_DUPLICATE");
      seen.add(key);
    }
  }
}
function analyzeLedger(
  source: TimelineSource, sourceId: string, rows: TimelineEvent[],
  expectation: ForensicLedgerExpectation | undefined,
  analyzedAt: string, add: (f: ForensicFinding) => void,
): ForensicLedger {
  const ordered = [...rows].sort((a, b) =>
    a.sourceRevision - b.sourceRevision || a.eventId.localeCompare(b.eventId));
  let conflicts = 0;
  let incomplete = 0;
  let unknown = 0;
  let findings = 0;
  const note = (
    code: ForensicFindingCode, severity: ForensicSeverity,
    event: TimelineEvent | null, explanation: string,
  ) => {
    if (severity === "CONFLICT") conflicts++;
    else if (severity === "UNKNOWN") unknown++;
    else incomplete++;
    findings++;
    add({ code, severity, source, sourceId,
      revision: event?.sourceRevision ?? null,
      eventId: event?.eventId ?? null, explanation });
  };
  if (!ordered.length && expectation) {
    note("MISSING_SOURCE", "UNKNOWN", null, "Expected ledger has no events");
  }
  if (ordered.length && ordered[0]!.sourceRevision !== 1) {
    note("FIRST_REVISION_MISSING", "INCOMPLETE", ordered[0]!,
      "First revision is not one; source history is incomplete");
  }
  const seenIds = new Set<string>();
  const seenRevisions = new Set<number>();
  let prev: TimelineEvent | null = null;
  let timestamps = [] as string[];
  for (const event of ordered) {
    timestamps.push(event.occurredAt);
    if (seenIds.has(event.eventId)) {
      note("EVENT_REUSED", "CONFLICT", event,
        "Event identifier is reused within the ledger");
    }
    seenIds.add(event.eventId);
    if (seenRevisions.has(event.sourceRevision)) {
      note("REVISION_DUPLICATE", "CONFLICT", event,
        "Multiple events claim the same source revision");
    }
    seenRevisions.add(event.sourceRevision);
    if (prev && event.sourceRevision !== prev.sourceRevision + 1 &&
        event.sourceRevision !== prev.sourceRevision) {
      note("REVISION_GAP", "INCOMPLETE", event,
        "An intermediate source revision is missing");
    }
    if (prev && event.occurredAt < prev.occurredAt) {
      note("EVENT_TIME_REGRESSION", "CONFLICT", event,
        "Source event timestamp moved backwards");
    }
    if (prev && event.priorDigest !== null &&
        event.priorDigest !== prev.nextDigest) {
      note("CHAIN_LINK_MISMATCH", "CONFLICT", event,
        "Previous snapshot digest does not match preceding tip");
    }
    if (!prev && event.sourceRevision === 1 &&
        event.priorDigest !== null) {
      // A create event may describe a previous imported object: remain
      // conservative rather than asserting evidence of tampering.
      note("ROOT_LINK_UNEXPECTED", "UNKNOWN", event,
        "First revision contains a predecessor digest");
    }
    if (event.sourceEventDigest === null) {
      note("MISSING_EVENT_DIGEST", "INCOMPLETE", event,
        "Source event cannot be independently rehashed by projection");
    }
    if (event.occurredAt > analyzedAt) {
      note("SOURCE_TIMESTAMP_IN_FUTURE", "UNKNOWN", event,
        "Source event is later than the forensic assessment clock");
    }
    if (event.providerWrites !== 0 ||
        event.providerOutcomeIndependentlyVerified !== false) {
      note("PROVIDER_ASSERTION_UNSUPPORTED", "CONFLICT", event,
        "Projection claims execution without provider evidence");
    }
    prev = event;
  }
  const tip = ordered.length ? ordered[ordered.length - 1]! : null;
  if (expectation) {
    if (!expectation.inventoryComplete) {
      note("LEDGER_INVENTORY_TRUNCATED", "UNKNOWN", tip,
        "Expected source inventory is not complete");
    }
    if (!tip || tip.sourceRevision !== expectation.expectedRevision) {
      note("SNAPSHOT_REVISION_MISMATCH", "INCOMPLETE", tip,
        "Snapshot revision cannot be reconciled with projected history");
    }
    if (expectation.expectedDigest !== null &&
        (!tip || tip.nextDigest !== expectation.expectedDigest)) {
      note("END_DIGEST_MISMATCH", "CONFLICT", tip,
        "Projected tip does not match persisted snapshot digest");
    }
  }
  const status: TimelineIntegrity = conflicts ? "CONFLICT" :
    incomplete || unknown ? "INCOMPLETE" : "VERIFIED";
  return {
    source, sourceId, firstRevision: ordered[0]?.sourceRevision ?? null,
    lastRevision: tip?.sourceRevision ?? null,
    expectedRevision: expectation?.expectedRevision ?? null,
    observedEvents: ordered.length,
    actorCount: new Set(ordered.map(x => x.actorUserId)).size,
    eventDigestCoverage: ordered.filter(x => x.sourceEventDigest !== null).length,
    firstAt: timestamps.length ? timestamps.sort()[0]! : null,
    lastAt: timestamps.length ? timestamps[timestamps.length - 1]! : null,
    rootDigest: ordered[0]?.priorDigest ?? null, tipDigest: tip?.nextDigest ?? null,
    status, findingCount: findings,
  };
}
export function inspectIncidentForensics(req: ForensicCaseRequest): ForensicCaseReport {
  validateForensicRequest(req);
  const findingBuffer: ForensicFinding[] = [];
  const push = (f: ForensicFinding) => findingBuffer.push(f);
  const grouped = new Map<string, TimelineEvent[]>();
  const expectationMap = new Map<string, ForensicLedgerExpectation>(
    (req.expectations ?? []).map(x =>
      [ledgerKey(x.source, x.sourceId), x] as const));
  let rejectedEvents = 0;
  const allEventIds = new Set<string>();
  for (const e of req.events) {
    const validation = verifyTimelineEvent(e);
    if (validation.length) {
      rejectedEvents++;
      push({ code: "ENTRY_INVALID", severity: "CONFLICT",
        source: allSources.includes(e.source) ? e.source : null,
        sourceId: id(e.sourceId) ? e.sourceId : null,
        revision: Number.isSafeInteger(e.sourceRevision) ?
          e.sourceRevision : null,
        eventId: id(e.eventId) ? e.eventId : null,
        explanation: validation.join(",") });
      continue;
    }
    if (allEventIds.has(e.eventId)) {
      push({ code: "EVENT_REUSED", severity: "CONFLICT",
        source: e.source, sourceId: e.sourceId,
        revision: e.sourceRevision, eventId: e.eventId,
        explanation: "Event identifier occurs in more than one source" });
    }
    allEventIds.add(e.eventId);
    const key = ledgerKey(e.source, e.sourceId);
    const bucket = grouped.get(key) ?? [];
    bucket.push(e);
    grouped.set(key, bucket);
  }
  for (const key of expectationMap.keys()) {
    if (!grouped.has(key)) grouped.set(key, []);
  }
  const ledgers: ForensicLedger[] = [];
  for (const [key, events] of grouped) {
    const event = events[0];
    const expected = expectationMap.get(key);
    const source = event?.source ?? expected!.source;
    const sourceId = event?.sourceId ?? expected!.sourceId;
    ledgers.push(analyzeLedger(source, sourceId, events, expected,
      req.analyzedAt, push));
  }
  ledgers.sort((a, b) => a.source.localeCompare(b.source) ||
    a.sourceId.localeCompare(b.sourceId));
  const coverage = Object.fromEntries(allSources.map(source => [
    source, ledgers.filter(x => x.source === source).length,
  ])) as Record<TimelineSource, number>;
  for (const source of req.requiredSources ?? []) {
    if (!coverage[source]) {
      push({ code: "MISSING_SOURCE", severity: "UNKNOWN",
        source, sourceId: null, revision: null, eventId: null,
        explanation: "Required source family has no persisted history" });
    }
  }
  if (!req.inventoryComplete) {
    push({ code: "LEDGER_INVENTORY_TRUNCATED", severity: "UNKNOWN",
      source: null, sourceId: null, revision: null, eventId: null,
      explanation: "Inventory completeness was not established" });
  }
  findingBuffer.sort(findingSort);
  const max = req.maxFindings ?? 250;
  const findingsTruncated = findingBuffer.length > max;
  const findings = findingBuffer.slice(0, max);
  // A digest of the complete finding inventory prevents treating a truncated
  // display as a complete attestation. It is a local consistency digest only.
  const digestPayload = {
    organizationId: req.organizationId, incidentId: req.incidentId,
    analyzedAt: req.analyzedAt, inventoryComplete: req.inventoryComplete,
    sourceEvents: req.events.length, rejectedEvents, ledgers,
    findingInventoryDigest: forensicDigest(findingBuffer),
  };
  const integrity: TimelineIntegrity =
    findingBuffer.some(x => x.severity === "CONFLICT") ||
    ledgers.some(x => x.status === "CONFLICT") ? "CONFLICT" :
    findingBuffer.length || ledgers.some(x => x.status === "INCOMPLETE") ?
      "INCOMPLETE" : "VERIFIED";
  return {
    schema: "cyberpilot.incident.timeline.forensic-report.v1",
    organizationId: req.organizationId, incidentId: req.incidentId,
    analyzedAt: req.analyzedAt, inventoryComplete: req.inventoryComplete,
    sourceEvents: req.events.length,
    acceptedEvents: req.events.length - rejectedEvents, rejectedEvents,
    ledgerCount: ledgers.length, sourceCoverage: coverage, integrity,
    ledgers, findings, findingsTruncated, digest: forensicDigest(digestPayload),
    externalActions: 0, independentProviderProof: false,
  };
}
export function compareForensicReports(
  before: ForensicCaseReport, after: ForensicCaseReport,
) {
  if (before.organizationId !== after.organizationId ||
      before.incidentId !== after.incidentId)
    fail("FORENSIC_COMPARE_CROSS_TENANT_OR_INCIDENT");
  const byKey = (report: ForensicCaseReport) =>
    new Map(report.ledgers.map(x => [ledgerKey(x.source, x.sourceId), x]));
  const earlier = byKey(before);
  const later = byKey(after);
  const changes = [...new Set([...earlier.keys(), ...later.keys()])].sort()
    .map(key => {
      const left = earlier.get(key);
      const right = later.get(key);
      return {
        source: (right ?? left)!.source,
        sourceId: (right ?? left)!.sourceId,
        previousRevision: left?.lastRevision ?? null,
        currentRevision: right?.lastRevision ?? null,
        previousStatus: left?.status ?? null,
        currentStatus: right?.status ?? null,
        eventDelta: (right?.observedEvents ?? 0) -
          (left?.observedEvents ?? 0),
        regressed: !!left && !!right &&
          (right.observedEvents < left.observedEvents ||
           (right.lastRevision ?? 0) < (left.lastRevision ?? 0)),
        changedTip: left?.tipDigest !== right?.tipDigest,
      };
    });
  return {
    schema: "cyberpilot.incident.timeline.forensic-diff.v1" as const,
    organizationId: after.organizationId, incidentId: after.incidentId,
    previousDigest: before.digest, currentDigest: after.digest,
    changes, regressions: changes.filter(x => x.regressed),
    providerOutcomesVerified: false as const,
  };
}
