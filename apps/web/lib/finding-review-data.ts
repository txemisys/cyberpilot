import { db } from "@cyberpilot/database";
import { normalizeRunbookSteps } from "./remediation-runbook";
import type { ReviewAction, ReviewEvidence, ReviewFinding } from "./finding-evidence-review";

export type ReviewListOptions = {
  includeResolved: boolean;
  severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  search?: string;
  limit: number;
  offset: number;
};
export type ReviewDataPage = {
  findings: ReviewFinding[];
  total: number;
  offset: number;
  limit: number;
};

export function parseReviewListOptions(input: URLSearchParams): ReviewListOptions {
  const rawLimit = Number(input.get("limit") ?? 25);
  const rawPage = Number(input.get("page") ?? 1);
  const limit = [10, 25, 50].includes(rawLimit) ? rawLimit : 25;
  const page = Number.isSafeInteger(rawPage) && rawPage > 0
    ? Math.min(10000, rawPage) : 1;
  const allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const severity = allowed.find(value => value === input.get("severity")) as
    ReviewListOptions["severity"];
  const search = (input.get("search") ?? "").trim().slice(0, 100);
  return {
    includeResolved: input.get("resolved") === "yes",
    severity,
    search: search || undefined,
    limit,
    offset: (page - 1) * limit,
  };
}

export function reviewListUrl(
  base: string,
  options: ReviewListOptions,
  page: number,
): string {
  const params = new URLSearchParams();
  params.set("page", String(Math.max(1, Math.floor(page))));
  params.set("limit", String(options.limit));
  if (options.includeResolved) params.set("resolved", "yes");
  if (options.severity) params.set("severity", options.severity);
  if (options.search) params.set("search", options.search);
  return base + "?" + params.toString();
}

type StoredEvidence = {
  id: string;
  domain: string;
  controlId: string;
  state: string;
  source: string;
  observedAt: Date | null;
  createdAt: Date;
};

export function classifyStoredEvidenceState(value: string): ReviewEvidence["source"] {
  switch (value.toUpperCase()) {
    case "OBSERVED":
      return "OBSERVED";
    case "DECLARED":
      return "DECLARED";
    case "ERROR":
      return "ERROR";
    default:
      return "UNKNOWN";
  }
}

function evidenceForFinding(
  finding: { ruleId: string; key: string; title: string },
  records: readonly StoredEvidence[],
): ReviewEvidence[] {
  // Control identifiers are not guaranteed to equal finding rule identifiers.
  // Exact control / rule matching is the only safe automatic attribution here.
  // Unmatched evidence is excluded rather than assigned to an unrelated finding.
  const matches = records.filter(record =>
    record.controlId === finding.ruleId ||
    record.controlId === finding.key,
  );
  return matches.map(record => ({
    id: record.id,
    source: classifyStoredEvidenceState(record.state),
    category: record.domain,
    capturedAt: record.createdAt,
    lastObservedAt: record.observedAt,
    summary: record.controlId + " — " + record.source,
  }));
}

export async function loadReviewData(
  organizationId: string,
  options: ReviewListOptions,
): Promise<ReviewDataPage> {
  if (!organizationId) throw new Error("Organization authorization is mandatory");
  const where = {
    organizationId,
    ...(options.includeResolved ? {} : { status: "OPEN" as const }),
    ...(options.severity ? { severity: options.severity } : {}),
    ...(options.search ? {
      OR: [
        { title: { contains: options.search, mode: "insensitive" as const } },
        { ruleId: { contains: options.search, mode: "insensitive" as const } },
        { description: { contains: options.search, mode: "insensitive" as const } },
      ],
    } : {}),
  };
  const [total, records] = await Promise.all([
    db.securityFinding.count({ where }),
    db.securityFinding.findMany({
      where,
      orderBy: [{ lastSeenAt: "desc" }, { id: "asc" }],
      skip: options.offset,
      take: options.limit,
      select: {
        id: true, key: true, ruleId: true, title: true, description: true,
        severity: true, status: true, firstSeenAt: true, lastSeenAt: true,
        resolvedAt: true,
        remediations: {
          select: {
            id: true, title: true, status: true, mode: true,
            createdAt: true, startedAt: true, completedAt: true,
            verifiedAt: true, approvedAt: true, steps: true,
            verification: true,
            guidedProgress: { select: { stepIndex: true } },
          },
          orderBy: [{ createdAt: "desc" }, { id: "asc" }],
          take: 100,
        },
      },
    }),
  ]);
  const controlIds = [...new Set(records.flatMap(item => [item.ruleId, item.key]))];
  const evidence = controlIds.length ? await db.securityEvidence.findMany({
    where: { organizationId, controlId: { in: controlIds } },
    take: 500,
    select: {
      id: true, domain: true, controlId: true, state: true,
      source: true, observedAt: true, createdAt: true,
    },
  }) : [];
  const findings: ReviewFinding[] = records.map(record => {
    const actions: ReviewAction[] = record.remediations.map(action => ({
      id: action.id,
      title: action.title,
      status: action.status,
      mode: action.mode,
      createdAt: action.createdAt,
      startedAt: action.startedAt,
      completedAt: action.completedAt,
      verifiedAt: action.verifiedAt,
      approvedAt: action.approvedAt,
      steps: normalizeRunbookSteps(action.steps),
      verification: normalizeRunbookSteps(action.verification),
      acknowledgedSteps: new Set(action.guidedProgress.map(step => step.stepIndex)),
    }));
    return {
      id: record.id,
      title: record.title,
      description: record.description,
      severity: record.severity,
      status: record.status,
      firstSeenAt: record.firstSeenAt,
      lastSeenAt: record.lastSeenAt,
      resolvedAt: record.resolvedAt,
      evidence: evidenceForFinding(record, evidence),
      actions,
    };
  });
  return { findings, total, offset: options.offset, limit: options.limit };
}

export async function loadSingleFindingReview(
  organizationId: string,
  findingId: string,
): Promise<ReviewFinding | null> {
  if (!organizationId || !findingId) return null;
  const record = await db.securityFinding.findFirst({
    where: { id: findingId, organizationId },
    select: { id: true },
  });
  if (!record) return null;
  // Read a bounded, one-record page from the same tenant-scoped source.
  // This preserves all normalization rules shared with the overview.
  const page = await db.securityFinding.findMany({
    where: { id: record.id, organizationId },
    select: {
      id: true, key: true, ruleId: true, title: true, description: true,
      severity: true, status: true, firstSeenAt: true, lastSeenAt: true,
      resolvedAt: true,
      remediations: {
        select: {
          id: true, title: true, status: true, mode: true,
          createdAt: true, startedAt: true, completedAt: true,
          verifiedAt: true, approvedAt: true, steps: true, verification: true,
          guidedProgress: { select: { stepIndex: true } },
        },
        take: 100,
        orderBy: [{ createdAt: "desc" }, { id: "asc" }],
      },
    },
  });
  const item = page[0];
  if (!item) return null;
  const observed = await db.securityEvidence.findMany({
    where: {
      organizationId,
      controlId: { in: [item.ruleId, item.key] },
    },
    take: 200,
    select: {
      id: true, domain: true, controlId: true, state: true,
      source: true, observedAt: true, createdAt: true,
    },
  });
  return {
    id: item.id,
    title: item.title,
    description: item.description,
    severity: item.severity,
    status: item.status,
    firstSeenAt: item.firstSeenAt,
    lastSeenAt: item.lastSeenAt,
    resolvedAt: item.resolvedAt,
    evidence: evidenceForFinding(item, observed),
    actions: item.remediations.map(action => ({
      id: action.id,
      title: action.title,
      status: action.status,
      mode: action.mode,
      createdAt: action.createdAt,
      startedAt: action.startedAt,
      completedAt: action.completedAt,
      verifiedAt: action.verifiedAt,
      approvedAt: action.approvedAt,
      steps: normalizeRunbookSteps(action.steps),
      verification: normalizeRunbookSteps(action.verification),
      acknowledgedSteps: new Set(action.guidedProgress.map(step => step.stepIndex)),
    })),
  };
}
