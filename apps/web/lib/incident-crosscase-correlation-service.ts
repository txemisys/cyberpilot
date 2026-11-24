import type { IncidentActor } from "./incident-case-service";
import { readOperationalTimeline } from "./incident-operational-timeline-service";
import {
  correlateSelectedIncidents, graphSelectedCorrelations,
  prepareCorrelationReviews, summarizeCorrelationByKind,
  exportCorrelationCSV, exportCorrelationJSON,
  type CorrelationCaseInput, type CorrelationPolicy,
  defaultCorrelationPolicy, validateCorrelationPolicy,
} from "./incident-crosscase-correlation-domain";
import type { TimelineEvent } from "./incident-operational-timeline-domain";

export class CrosscaseCorrelationError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => {
  throw new CrosscaseCorrelationError(code);
};
const ident = (x: unknown): x is string =>
  typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);

/**
 * The actor explicitly supplies every incident id. This service does not
 * scan organization incidents or infer access across organizations.
 */
export async function readSelectedIncidentCorrelations(
  actor: IncidentActor,
  incidentIds: string[],
  policy: CorrelationPolicy = defaultCorrelationPolicy(),
) {
  if (!actor || !ident(actor.organizationId) ||
      !ident(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("CORRELATION_ACTOR_DENIED");
  if (validateCorrelationPolicy(policy).length)
    fail("CORRELATION_POLICY_REJECTED");
  if (!Array.isArray(incidentIds) || incidentIds.length < 2 ||
      incidentIds.length > policy.maximumCases ||
      incidentIds.some(id => !ident(id)) ||
      new Set(incidentIds).size !== incidentIds.length)
    fail("CORRELATION_EXPLICIT_SELECTION_INVALID");
  const cases: CorrelationCaseInput[] = [];
  for (const incidentId of incidentIds) {
    const entries: TimelineEvent[] = [];
    let cursor: string | null = null;
    let complete = false;
    let baselineDigest: string | null = null;
    let forensic: CorrelationCaseInput["forensic"] | null = null;
    let revision = 0;
    let pageCount = 0;
    do {
      // Every read performs server-side membership and incident scope checks.
      const current = await readOperationalTimeline(actor, incidentId, {
        limit: 100, ...(cursor ? { cursor } : {}),
      });
      if (baselineDigest && baselineDigest !== current.page.queryDigest)
        fail("CORRELATION_SNAPSHOT_CHANGED_DURING_PAGING");
      if (!baselineDigest) baselineDigest = current.page.queryDigest;
      if (revision && revision !== current.page.incidentRevision)
        fail("CORRELATION_INCIDENT_CHANGED_DURING_PAGING");
      revision = current.page.incidentRevision;
      forensic ??= current.forensics;
      if (current.page.entries.some(entry =>
          entry.organizationId !== actor.organizationId ||
          entry.incidentId !== incidentId))
        fail("CORRELATION_SOURCE_SCOPE_VIOLATION");
      entries.push(...current.page.entries);
      cursor = current.page.nextCursor;
      pageCount++;
      if (entries.length > policy.maximumEventsPerCase)
        fail("CORRELATION_SOURCE_EVENT_CAP_EXCEEDED");
      complete = !cursor && current.page.completeness === "COMPLETE";
      if (pageCount > Math.ceil(policy.maximumEventsPerCase / 100) + 1)
        fail("CORRELATION_PAGING_LIMIT_EXCEEDED");
    } while (cursor);
    if (!forensic || !revision)
      fail("CORRELATION_INCIDENT_HISTORY_UNAVAILABLE");
    cases.push({
      incidentId, incidentRevision: revision,
      timelineEvents: entries, forensic,
      eventInventoryComplete: complete,
    });
  }
  const report = correlateSelectedIncidents({
    organizationId: actor.organizationId,
    requestedAt: new Date().toISOString(), cases, policy,
  });
  const graph = graphSelectedCorrelations(report);
  const reviews = prepareCorrelationReviews(report);
  const byKind = summarizeCorrelationByKind(report);
  return {
    report, graph, reviews, byKind, providerWrites: 0 as const,
    claimsOfSharedCompromise: 0 as const,
    selectionRequired: true as const,
    limitations: [
      "El operador debe seleccionar explícitamente al menos dos incidentes",
      "No hay descubrimiento automático del tenant completo",
      "Un actor repetido podría ser el mismo operador interno",
      "Las claves compartidas no acreditan identidad física ni lógica",
      "La proximidad temporal no prueba una campaña común",
      "No se ejecuta ninguna contención externa",
    ],
  };
}
export async function exportSelectedIncidentCorrelations(
  actor: IncidentActor,
  incidentIds: string[], format: "json" | "csv",
  policy?: CorrelationPolicy,
) {
  const read = await readSelectedIncidentCorrelations(
    actor, incidentIds, policy);
  return {
    mime: format === "csv" ? "text/csv; charset=utf-8" :
      "application/json; charset=utf-8",
    content: format === "csv" ?
      exportCorrelationCSV(read.report) :
      exportCorrelationJSON(read.report),
    digest: read.report.digest,
    externalWrites: 0 as const,
  };
}
