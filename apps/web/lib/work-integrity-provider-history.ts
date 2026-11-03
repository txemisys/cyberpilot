import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Historical provider verification transitions are facts about stored
 * checks, not an estimate of how long the external control was secure.
 * The observation time is the time of the HTTP read, not the interval
 * between checks.
 */
export type ProviderTransition =
  | "FIRST_OBSERVATION" | "PASS_TO_FAIL" | "FAIL_TO_PASS"
  | "RECOVERED_PROVIDER" | "PROVIDER_INTERRUPTED"
  | "BECAME_INCONCLUSIVE" | "RESOLVED_INCONCLUSIVE"
  | "UNCHANGED" | "OTHER_CHANGE";
export type ProviderHistoryQuery = {
  taskId: string;
  evidenceId?: string;
  offset: number;
  limit: number;
  from?: Date;
  to?: Date;
};
export type ProviderHistoryPoint = {
  id: string;
  evidenceId: string;
  provider: string;
  subject: string;
  controlId: string;
  outcome: string;
  checkedAt: string;
  providerObservedAt: string | null;
  observationDigest: string;
  responseDigest: string;
  failureCode: string | null;
  transition: ProviderTransition;
  previousCheckId: string | null;
  previousOutcome: string | null;
  observationChanged: boolean | null;
  intervalMinutes: number | null;
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid provider history query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
function date(value: unknown, label: string): Date | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value))
    throw new WorkInputError("INVALID", "Invalid " + label + " timestamp.");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()))
    throw new WorkInputError("INVALID", "Invalid " + label + " timestamp.");
  return parsed;
}
export function parseProviderHistoryQuery(
  value: unknown,
): ProviderHistoryQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "taskId", "evidenceId", "offset", "limit", "from", "to",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown provider history filter.");
  const from = date(raw.from, "from");
  const to = date(raw.to, "to");
  if (from && to && from.getTime() > to.getTime())
    throw new WorkInputError("INVALID", "Invalid provider history interval.");
  return {
    taskId: parseWorkId(raw.taskId, "review task ID"),
    ...(raw.evidenceId === undefined ? {} : {
      evidenceId: parseWorkId(raw.evidenceId, "evidence ID"),
    }),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 200),
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
  };
}
export type ProviderHistoryRecord = {
  id: string; evidenceId: string;
  provider: string; subject: string; controlId: string;
  outcome: string; checkedAt: Date; providerObservedAt: Date | null;
  observationDigest: string; responseDigest: string;
  failureCode: string | null;
};
export function classifyProviderTransition(
  previous: ProviderHistoryRecord | null,
  current: ProviderHistoryRecord,
): ProviderTransition {
  if (!previous) return "FIRST_OBSERVATION";
  if (previous.outcome === current.outcome) return "UNCHANGED";
  if (previous.outcome === "PASS" && current.outcome === "FAIL")
    return "PASS_TO_FAIL";
  if (previous.outcome === "FAIL" && current.outcome === "PASS")
    return "FAIL_TO_PASS";
  if (previous.outcome === "PROVIDER_ERROR" &&
      current.outcome !== "PROVIDER_ERROR")
    return "RECOVERED_PROVIDER";
  if (previous.outcome !== "PROVIDER_ERROR" &&
      current.outcome === "PROVIDER_ERROR")
    return "PROVIDER_INTERRUPTED";
  if (current.outcome === "INCONCLUSIVE")
    return "BECAME_INCONCLUSIVE";
  if (previous.outcome === "INCONCLUSIVE")
    return "RESOLVED_INCONCLUSIVE";
  return "OTHER_CHANGE";
}
export function buildProviderHistory(
  records: ProviderHistoryRecord[],
  previousByEvidence = new Map<string, ProviderHistoryRecord>(),
): ProviderHistoryPoint[] {
  const sorted = [...records].sort((a, b) =>
    a.checkedAt.getTime() - b.checkedAt.getTime() ||
    a.id.localeCompare(b.id));
  const result: ProviderHistoryPoint[] = [];
  for (const current of sorted) {
    const previous = previousByEvidence.get(current.evidenceId) ?? null;
    result.push({
      id: current.id,
      evidenceId: current.evidenceId,
      provider: current.provider,
      subject: current.subject,
      controlId: current.controlId,
      outcome: current.outcome,
      checkedAt: current.checkedAt.toISOString(),
      providerObservedAt: current.providerObservedAt?.toISOString() ?? null,
      observationDigest: current.observationDigest,
      responseDigest: current.responseDigest,
      failureCode: current.failureCode,
      transition: classifyProviderTransition(previous, current),
      previousCheckId: previous?.id ?? null,
      previousOutcome: previous?.outcome ?? null,
      observationChanged: previous ?
        previous.observationDigest !== current.observationDigest : null,
      intervalMinutes: previous ?
        (current.checkedAt.getTime() -
          previous.checkedAt.getTime()) / 60000 : null,
    });
    previousByEvidence.set(current.evidenceId, current);
  }
  return result;
}
export async function inspectProviderHistory(
  scope: ReviewScope, value: unknown,
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Provider history denied.");
  const query = parseProviderHistoryQuery(value);
  const task = await db.integrityReviewTask.findFirst({
    where: {
      id: query.taskId, organizationId: scope.organizationId,
    },
    select: { id: true, captureId: true, disposition: true },
  });
  if (!task)
    throw new WorkInputError("MISSING", "Review task not found.");
  const where = {
    organizationId: scope.organizationId,
    taskId: query.taskId,
    ...(query.evidenceId ? { evidenceId: query.evidenceId } : {}),
    ...(query.from || query.to ? {
      checkedAt: {
        ...(query.from ? { gte: query.from } : {}),
        ...(query.to ? { lte: query.to } : {}),
      },
    } : {}),
  };
  const [total, page] = await db.$transaction([
    db.integrityProviderCheck.count({ where }),
    db.integrityProviderCheck.findMany({
      where,
      orderBy: [{ checkedAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, evidenceId: true, provider: true,
        subject: true, controlId: true, outcome: true,
        checkedAt: true, providerObservedAt: true,
        observationDigest: true, responseDigest: true,
        failureCode: true,
      },
    }),
  ]);
  const ids = [...new Set(page.map(row => row.evidenceId))];
  // Predecessors are resolved per evidence record. This avoids presenting
  // the first entry on a paginated page as a new first observation.
  const predecessors = await Promise.all(ids.map(async evidenceId => {
    const first = page.find(row => row.evidenceId === evidenceId)!;
    const previous = await db.integrityProviderCheck.findFirst({
      where: {
        organizationId: scope.organizationId,
        taskId: query.taskId, evidenceId,
        OR: [
          { checkedAt: { lt: first.checkedAt } },
          {
            checkedAt: first.checkedAt,
            id: { lt: first.id },
          },
        ],
      },
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, evidenceId: true, provider: true,
        subject: true, controlId: true, outcome: true,
        checkedAt: true, providerObservedAt: true,
        observationDigest: true, responseDigest: true,
        failureCode: true,
      },
    });
    return { evidenceId, previous };
  }));
  const prior = new Map<string, ProviderHistoryRecord>();
  for (const item of predecessors) {
    if (item.previous)
      prior.set(item.evidenceId, item.previous);
  }
  const points = buildProviderHistory(page, prior);
  const transitions: Record<ProviderTransition, number> = {
    FIRST_OBSERVATION: 0, PASS_TO_FAIL: 0,
    FAIL_TO_PASS: 0, RECOVERED_PROVIDER: 0,
    PROVIDER_INTERRUPTED: 0, BECAME_INCONCLUSIVE: 0,
    RESOLVED_INCONCLUSIVE: 0, UNCHANGED: 0,
    OTHER_CHANGE: 0,
  };
  for (const point of points) transitions[point.transition]++;
  const latestByEvidence = new Map<string, ProviderHistoryPoint>();
  for (const point of points)
    latestByEvidence.set(point.evidenceId, point);
  return {
    task, total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + points.length < total,
    from: query.from?.toISOString() ?? null,
    to: query.to?.toISOString() ?? null,
    points,
    transitions,
    latestOnPage: [...latestByEvidence.values()],
    limitations: [
      "Transitions compare discrete provider observations, not continuous monitoring.",
      "A change between checks does not identify when the control changed.",
      "Counts and latestOnPage describe the requested page only.",
      "No remote call is performed when reading provider history.",
    ],
  };
}
