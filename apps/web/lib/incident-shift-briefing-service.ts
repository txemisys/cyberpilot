import type { IncidentActor } from "./incident-case-service";
import { readOperationalTimeline } from "./incident-operational-timeline-service";
import {
  buildIncidentShiftBriefing, shiftRoleWorkload, shiftProofMatrix,
  shiftPrioritizedQueue, exportShiftJSON, exportShiftWorkCSV,
  exportShiftMarkdown, type ShiftWindow, type ShiftPolicy,
  defaultShiftPolicy,
} from "./incident-shift-briefing-domain";
import type { TimelineEvent } from "./incident-operational-timeline-domain";

export class ShiftBriefingServiceError extends Error {
  constructor(public readonly code: string) { super(code); }
}
const fail = (code: string): never => {
  throw new ShiftBriefingServiceError(code);
};
const id = (x: unknown): x is string => typeof x === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const maxEntries = 1000;

/**
 * Read authenticated event pages with a stable query digest. Any concurrent
 * revision invalidates the entire briefing instead of silently mixing states.
 */
async function readShiftSources(actor: IncidentActor, incidentId: string) {
  const events: TimelineEvent[] = [];
  let cursor: string | null = null;
  let previousQueryDigest: string | null = null;
  let forensic: Awaited<ReturnType<typeof readOperationalTimeline>>["forensics"] | null = null;
  let investigation: Awaited<ReturnType<typeof readOperationalTimeline>>["investigation"] | null = null;
  let revision = 0;
  do {
    const read = await readOperationalTimeline(actor, incidentId, {
      limit: 100, ...(cursor ? { cursor } : {}),
    });
    if (previousQueryDigest &&
        previousQueryDigest !== read.page.queryDigest)
      fail("SHIFT_SOURCE_CHANGED_DURING_PAGING");
    if (!previousQueryDigest)
      previousQueryDigest = read.page.queryDigest;
    if (revision && revision !== read.page.incidentRevision)
      fail("SHIFT_INCIDENT_REVISION_CHANGED");
    revision = read.page.incidentRevision;
    forensic ??= read.forensics;
    investigation ??= read.investigation;
    if (read.page.entries.some(x =>
      x.organizationId !== actor.organizationId ||
      x.incidentId !== incidentId))
      fail("SHIFT_EVENT_SCOPE_VIOLATION");
    events.push(...read.page.entries);
    if (events.length > maxEntries)
      fail("SHIFT_EVENT_CAP_EXCEEDED");
    cursor = read.page.nextCursor;
  } while (cursor);
  if (!forensic || !investigation || !revision)
    fail("SHIFT_SOURCE_UNAVAILABLE");
  return { events, forensic, investigation, revision };
}
export async function readIncidentShiftBriefing(
  actor: IncidentActor, incidentId: string,
  window: ShiftWindow,
  policy: ShiftPolicy = defaultShiftPolicy(),
) {
  if (!actor || !id(actor.organizationId) || !id(actor.userId) ||
      !["OWNER", "ADMIN", "AUDITOR"].includes(actor.role))
    fail("SHIFT_ROLE_DENIED");
  if (!id(incidentId)) fail("SHIFT_INCIDENT_ID_INVALID");
  const source = await readShiftSources(actor, incidentId);
  const briefing = buildIncidentShiftBriefing({
    organizationId: actor.organizationId, incidentId,
    incidentRevision: source.revision,
    window, policy, events: source.events,
    forensics: source.forensic, investigation: source.investigation,
  });
  return {
    briefing, workload: shiftRoleWorkload(briefing),
    proofMatrix: shiftProofMatrix(briefing),
    priorityQueue: shiftPrioritizedQueue(briefing),
    limitations: [
      "Este documento es una proyección interna del historial autorizado",
      "Ningún operador ha aceptado el relevo por esta lectura",
      "Las tareas son sugerencias pendientes de asignación humana",
      "Ningún proveedor confirma éxito de aislamiento o remediación",
    ],
    persistedAcceptance: false as const,
    externalNotifications: 0 as const,
    providerWrites: 0 as const,
  };
}
export async function exportIncidentShiftBriefing(
  actor: IncidentActor, incidentId: string,
  window: ShiftWindow, format: "json" | "csv" | "md",
) {
  const read = await readIncidentShiftBriefing(actor, incidentId, window);
  const content = format === "json" ?
    exportShiftJSON(read.briefing) : format === "csv" ?
      exportShiftWorkCSV(read.briefing) :
      exportShiftMarkdown(read.briefing);
  return {
    digest: read.briefing.digest, content,
    mime: format === "json" ? "application/json; charset=utf-8" :
      format === "csv" ? "text/csv; charset=utf-8" :
      "text/markdown; charset=utf-8",
    externallyExecuted: false as const,
  };
}
