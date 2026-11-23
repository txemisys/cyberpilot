import { createHash } from "node:crypto";
import {
  reportDescriptor, verifyOfflineCapture,
  type OfflineCapture, type OfflineCaptureKind,
} from "./offline-report-capture-domain";

/**
 * Bounded, source-verified historical analysis of stored offline reports.
 *
 * A change in counts is a historical difference, NOT evidence of
 * remediation, threat reduction, customer attestation or LIVE coverage.
 */
export type CaptureTimelineQuery = {
  organizationId: string;
  kind?: OfflineCaptureKind;
  from?: string;
  until?: string;
  completeOnly?: boolean;
  offset?: number;
  limit?: number;
};
export type CaptureTimelinePoint = {
  id: string;
  organizationId: string;
  kind: OfflineCaptureKind;
  capturedAt: string;
  createdAt: string;
  reportSchema: string;
  reportDigest: string;
  payloadDigest: string;
  sourceComplete: boolean;
  integrityValid: boolean;
  recordCount: number;
  riskCount: number;
  declaredComplete: number;
  trendSnapshots: number;
  sourceClasses: string[];
  sourceClassCount: number;
  duplicatedDigest: boolean;
  sourceAgeMilliseconds: number | null;
};
export type TimelineChange = {
  earlierId: string;
  laterId: string;
  earlierAt: string;
  laterAt: string;
  kind: OfflineCaptureKind;
  comparable: boolean;
  reasons: string[];
  elapsedMilliseconds: number;
  recordCountDelta: number | null;
  riskCountDelta: number | null;
  declaredCompleteDelta: number | null;
  trendSnapshotsDelta: number | null;
  sourceClassesAdded: string[];
  sourceClassesRemoved: string[];
  digestChanged: boolean;
  historicalChangeObserved: boolean;
  independentlyVerifiedImprovement: false;
};
export type TimelineKindStats = {
  kind: OfflineCaptureKind;
  count: number;
  complete: number;
  invalid: number;
  distinctSourceDigests: number;
  schemaVersions: string[];
  oldest: string | null;
  newest: string | null;
  comparableTransitions: number;
  incomparableTransitions: number;
  changes: number;
  gapsOver30Days: number;
  earliestRecordCount: number | null;
  latestRecordCount: number | null;
  netRecordDelta: number | null;
  earliestRiskCount: number | null;
  latestRiskCount: number | null;
  netRiskDelta: number | null;
};
export type CaptureTimeline = {
  schema: "cyberpilot.offline.capture.timeline.v1";
  organizationId: string;
  evaluatedAt: string;
  query: CaptureTimelineQuery;
  totalMatched: number;
  offset: number;
  limit: number;
  nextOffset: number | null;
  truncated: boolean;
  points: CaptureTimelinePoint[];
  changes: TimelineChange[];
  kinds: TimelineKindStats[];
  integrityIssues: string[];
  omittedInvalidCaptures: number;
  sourceEvidenceOnly: true;
  providerCalls: 0;
  independentRemediationVerified: false;
  liveCustomerAttestation: false;
  cyberScoreV1Writes: 0;
};
export type TimelineExport = {
  filename: string;
  mime: string;
  content: string;
  truncated: boolean;
  completenessWarning: boolean;
};
const kinds = [
  "INTEGRATED_RISKS", "EVIDENCE_DECISIONS", "EXECUTIVE", "LONGITUDINAL",
] as const;
const key = (x: unknown) => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso = (x: unknown): x is string =>
  typeof x === "string" && Number.isFinite(Date.parse(x)) &&
  new Date(x).toISOString() === x;
const sha = (x: string) => createHash("sha256").update(x).digest("hex");

export function validateTimelineQuery(query: CaptureTimelineQuery): string[] {
  const issues: string[] = [];
  if (!query || !key(query.organizationId))
    issues.push("TIMELINE_TENANT_INVALID");
  if (query.kind !== undefined && !kinds.includes(query.kind))
    issues.push("TIMELINE_KIND_INVALID");
  if (query.from !== undefined && !iso(query.from))
    issues.push("TIMELINE_FROM_INVALID");
  if (query.until !== undefined && !iso(query.until))
    issues.push("TIMELINE_UNTIL_INVALID");
  if (query.from && query.until && query.from > query.until)
    issues.push("TIMELINE_RANGE_INVALID");
  if (query.completeOnly !== undefined &&
      typeof query.completeOnly !== "boolean")
    issues.push("TIMELINE_COMPLETENESS_INVALID");
  if (query.offset !== undefined &&
      (!Number.isSafeInteger(query.offset) || query.offset < 0 ||
       query.offset > 100000))
    issues.push("TIMELINE_OFFSET_INVALID");
  if (query.limit !== undefined &&
      (!Number.isSafeInteger(query.limit) || query.limit < 1 ||
       query.limit > 200))
    issues.push("TIMELINE_LIMIT_INVALID");
  return issues;
}
function safeCount(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) &&
    value >= 0 ? value : 0;
}
function safeSourceClasses(classes: unknown): string[] {
  if (!Array.isArray(classes)) return [];
  return [...new Set(classes.filter((x): x is string =>
    typeof x === "string" && x.length > 0 && x.length < 300))].sort();
}
function point(capture: OfflineCapture, evaluation: string,
  duplicatedDigest: boolean): CaptureTimelinePoint {
  const validation = verifyOfflineCapture(capture, capture.organizationId);
  const description = reportDescriptor(capture.payload.report);
  const age = Date.parse(evaluation) - Date.parse(capture.payload.capturedAt);
  return {
    id: capture.id,
    organizationId: capture.organizationId,
    kind: capture.kind,
    capturedAt: capture.payload.capturedAt,
    createdAt: capture.createdAt,
    reportSchema: capture.schemaVersion,
    reportDigest: capture.originalDigest,
    payloadDigest: capture.payloadDigest,
    sourceComplete: capture.sourceComplete,
    integrityValid: validation.valid,
    recordCount: safeCount(description.recordCount),
    riskCount: safeCount(description.riskCount),
    declaredComplete: safeCount(description.declaredComplete),
    trendSnapshots: safeCount(description.trendSnapshots),
    sourceClasses: safeSourceClasses(description.sourceClasses),
    sourceClassCount: safeSourceClasses(description.sourceClasses).length,
    duplicatedDigest,
    sourceAgeMilliseconds: Number.isFinite(age) && age >= 0 ? age : null,
  };
}
export function compareTimelinePoints(
  earlier: CaptureTimelinePoint,
  later: CaptureTimelinePoint,
): TimelineChange {
  const reasons: string[] = [];
  if (earlier.organizationId !== later.organizationId)
    reasons.push("CROSS_TENANT_PAIR");
  if (earlier.kind !== later.kind)
    reasons.push("MIXED_KIND_PAIR");
  if (earlier.reportSchema !== later.reportSchema)
    reasons.push("SCHEMA_VERSION_CHANGED");
  if (!earlier.sourceComplete || !later.sourceComplete)
    reasons.push("INCOMPLETE_SOURCE");
  if (!earlier.integrityValid || !later.integrityValid)
    reasons.push("INTEGRITY_UNVERIFIED");
  if (earlier.capturedAt > later.capturedAt)
    reasons.push("REVERSED_CAPTURE_TIME");
  const elapsed = Date.parse(later.capturedAt) -
    Date.parse(earlier.capturedAt);
  if (!Number.isFinite(elapsed) || elapsed < 0)
    reasons.push("INVALID_ELAPSED_TIME");
  if (earlier.duplicatedDigest || later.duplicatedDigest)
    reasons.push("REPEATED_SOURCE_DIGEST");
  const comparable = reasons.length === 0;
  const oldClasses = new Set(earlier.sourceClasses);
  const newClasses = new Set(later.sourceClasses);
  return {
    earlierId: earlier.id,
    laterId: later.id,
    earlierAt: earlier.capturedAt,
    laterAt: later.capturedAt,
    kind: later.kind,
    comparable,
    reasons,
    elapsedMilliseconds: Number.isFinite(elapsed) && elapsed >= 0 ?
      elapsed : 0,
    recordCountDelta: comparable ?
      later.recordCount - earlier.recordCount : null,
    riskCountDelta: comparable ?
      later.riskCount - earlier.riskCount : null,
    declaredCompleteDelta: comparable ?
      later.declaredComplete - earlier.declaredComplete : null,
    trendSnapshotsDelta: comparable ?
      later.trendSnapshots - earlier.trendSnapshots : null,
    sourceClassesAdded: comparable ?
      later.sourceClasses.filter(x => !oldClasses.has(x)) : [],
    sourceClassesRemoved: comparable ?
      earlier.sourceClasses.filter(x => !newClasses.has(x)) : [],
    digestChanged: earlier.reportDigest !== later.reportDigest,
    historicalChangeObserved: comparable &&
      earlier.reportDigest !== later.reportDigest,
    independentlyVerifiedImprovement: false,
  };
}
function statsFor(kind: OfflineCaptureKind,
  points: CaptureTimelinePoint[],
  transitions: TimelineChange[]): TimelineKindStats {
  const selected = points.filter(x => x.kind === kind);
  const first = selected[0];
  const last = selected.at(-1);
  const transitionsForKind = transitions.filter(x => x.kind === kind);
  const firstComparable = selected.find(x => x.sourceComplete && x.integrityValid);
  const lastComparable = [...selected].reverse().find(x =>
    x.sourceComplete && x.integrityValid &&
    x.reportSchema === firstComparable?.reportSchema);
  const coherent = firstComparable && lastComparable &&
    selected.every(x => x.sourceComplete && x.integrityValid &&
      x.reportSchema === firstComparable.reportSchema);
  return {
    kind,
    count: selected.length,
    complete: selected.filter(x => x.sourceComplete).length,
    invalid: selected.filter(x => !x.integrityValid).length,
    distinctSourceDigests: new Set(selected.map(x => x.reportDigest)).size,
    schemaVersions: [...new Set(selected.map(x => x.reportSchema))].sort(),
    oldest: first?.capturedAt ?? null,
    newest: last?.capturedAt ?? null,
    comparableTransitions: transitionsForKind.filter(x => x.comparable).length,
    incomparableTransitions: transitionsForKind.filter(x => !x.comparable).length,
    changes: transitionsForKind.filter(x => x.historicalChangeObserved).length,
    gapsOver30Days: transitionsForKind.filter(x =>
      x.elapsedMilliseconds > 30 * 24 * 60 * 60 * 1000).length,
    earliestRecordCount: coherent ? firstComparable.recordCount : null,
    latestRecordCount: coherent ? lastComparable.recordCount : null,
    netRecordDelta: coherent ?
      lastComparable.recordCount - firstComparable.recordCount : null,
    earliestRiskCount: coherent ? firstComparable.riskCount : null,
    latestRiskCount: coherent ? lastComparable.riskCount : null,
    netRiskDelta: coherent ?
      lastComparable.riskCount - firstComparable.riskCount : null,
  };
}
export function buildCaptureTimeline(
  query: CaptureTimelineQuery,
  allCaptures: readonly OfflineCapture[],
  evaluatedAt: string,
  hasMore: boolean,
): CaptureTimeline {
  const issues = validateTimelineQuery(query);
  if (!iso(evaluatedAt)) issues.push("TIMELINE_EVALUATION_INVALID");
  if (allCaptures.length > 201)
    issues.push("TIMELINE_INPUT_UNBOUNDED");
  if (issues.length) throw Error(issues.join(","));
  if (allCaptures.some(x => x.organizationId !== query.organizationId))
    throw Error("TIMELINE_CROSS_TENANT_SOURCE");
  const selected = allCaptures.filter(x =>
    (!query.kind || x.kind === query.kind) &&
    (query.completeOnly !== true || x.sourceComplete) &&
    (!query.from || x.createdAt >= query.from) &&
    (!query.until || x.createdAt <= query.until));
  const ordered = [...selected].sort((a,b) =>
    a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id));
  const digestCounts = new Map<string, number>();
  for (const capture of ordered) {
    const identity = capture.kind + ":" + capture.originalDigest;
    digestCounts.set(identity, (digestCounts.get(identity) ?? 0) + 1);
  }
  const points = ordered.map(x => point(x,evaluatedAt,
    (digestCounts.get(x.kind + ":" + x.originalDigest) ?? 0) > 1));
  const changes: TimelineChange[] = [];
  for (const kind of kinds) {
    const series = points.filter(x => x.kind === kind);
    for (let index = 1; index < series.length; index++) {
      changes.push(compareTimelinePoints(series[index - 1]!, series[index]!));
    }
  }
  const invalid = points.filter(x => !x.integrityValid);
  const limit = query.limit ?? 100;
  const offset = query.offset ?? 0;
  const truncated = hasMore || selected.length > limit;
  const sliced = points.slice(0,limit);
  const allowedIds = new Set(sliced.map(x => x.id));
  const selectedChanges = changes.filter(x =>
    allowedIds.has(x.earlierId) && allowedIds.has(x.laterId));
  return {
    schema: "cyberpilot.offline.capture.timeline.v1",
    organizationId: query.organizationId,
    evaluatedAt,
    query,
    totalMatched: selected.length,
    offset,limit,
    nextOffset: truncated ? offset + limit : null,
    truncated,
    points: sliced,
    changes: selectedChanges,
    kinds: kinds.map(kind => statsFor(kind,sliced,selectedChanges)),
    integrityIssues: [
      ...invalid.map(x => "CAPTURE_INVALID:" + x.id),
      ...(hasMore ? ["TIMELINE_PAGE_HAS_MORE"] : []),
    ],
    omittedInvalidCaptures: invalid.filter(x => !allowedIds.has(x.id)).length,
    sourceEvidenceOnly: true,
    providerCalls: 0,
    independentRemediationVerified: false,
    liveCustomerAttestation: false,
    cyberScoreV1Writes: 0,
  };
}
const quote = (x: unknown) =>
  '"' + String(x ?? "").replaceAll('"','""')
    .replace(/^[=+@\-\t\r]/,"'&") + '"';
export function exportCaptureTimeline(
  timeline: CaptureTimeline,
  format: "JSON" | "CSV" | "MARKDOWN",
): TimelineExport {
  const safe = timeline.organizationId.replace(/[^a-zA-Z0-9_-]/g,"_").slice(0,64);
  const marker = timeline.evaluatedAt.slice(0,10);
  const warning = timeline.truncated ||
    timeline.points.some(x => !x.sourceComplete || !x.integrityValid);
  const prefix = "offline-capture-timeline-" + safe + "-" + marker;
  if (format === "JSON") return {
    filename:prefix+".json",
    mime:"application/json",
    content:JSON.stringify(timeline,null,2),
    truncated:timeline.truncated,
    completenessWarning:warning,
  };
  if (format === "CSV") {
    const header = [
      "id","kind","createdAt","schema","sourceComplete","integrityValid",
      "sourceClasses","recordCount","riskCount","declaredComplete",
      "trendSnapshots","reportDigest","payloadDigest",
    ];
    const rows = timeline.points.map(x => [
      x.id,x.kind,x.createdAt,x.reportSchema,x.sourceComplete,
      x.integrityValid,x.sourceClasses.join(";"),x.recordCount,
      x.riskCount,x.declaredComplete,x.trendSnapshots,
      x.reportDigest,x.payloadDigest,
    ].map(quote).join(","));
    return {
      filename:prefix+".csv",mime:"text/csv",
      content:[header.join(","),...rows].join("\n"),
      truncated:timeline.truncated,completenessWarning:warning,
    };
  }
  if (format !== "MARKDOWN") throw Error("TIMELINE_FORMAT_UNSUPPORTED");
  const lines = [
    "# Offline report capture timeline",
    "Organization: "+timeline.organizationId,
    "Evaluated: "+timeline.evaluatedAt,
    "Stored captures in page: "+timeline.points.length,
    "Pagination incomplete: "+String(timeline.truncated),
    "Integrity issues: "+timeline.integrityIssues.length,
    "",
    "| Kind | Captures | Complete | Invalid | Changes |",
    "| --- | ---: | ---: | ---: | ---: |",
    ...timeline.kinds.map(x =>
      "| "+x.kind+" | "+x.count+" | "+x.complete+" | "+
      x.invalid+" | "+x.changes+" |"),
    "",
    "Historical count changes do not prove remediation, customer consent or LIVE security posture.",
  ];
  return {
    filename:prefix+".md",mime:"text/markdown",
    content:lines.join("\n"),
    truncated:timeline.truncated,completenessWarning:warning,
  };
}
export function timelineFingerprint(timeline: CaptureTimeline) {
  return sha(JSON.stringify({
    organizationId:timeline.organizationId,
    evaluatedAt:timeline.evaluatedAt,
    entries:timeline.points.map(x=>({
      id:x.id,payloadDigest:x.payloadDigest,reportDigest:x.reportDigest,
      integrityValid:x.integrityValid,
    })),
    truncated:timeline.truncated,
  }));
}
