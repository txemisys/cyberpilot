import { db } from "@cyberpilot/database";
import { canReadWork, parseWorkId, WorkInputError } from "./remediation-work-input";
import { evaluateTechnicalGate } from "./work-integrity-provider-gates";
import {
  evaluateWorkReadiness, type WorkReadinessRecord,
  type ReadinessState,
} from "./work-integrity-provider-work-readiness";
import type { ReviewScope } from "./work-integrity-persistent-review";

/**
 * Capture-wide operational verification gaps.
 *
 * Queries are batched by the selected task page and organization. The report
 * is read-only; it does not imply that a missing check is a failing control.
 */
export type CaptureVerificationGap =
  | "NO_EVIDENCE" | "NO_PROVIDER_CHECK" | "PROVIDER_ERROR"
  | "PROVIDER_FAILED" | "PROVIDER_INCONCLUSIVE"
  | "PROVIDER_EXPIRED" | "EVIDENCE_CHANGED"
  | "PROVIDER_PASS" | "WORK_NOT_LINKED"
  | "WORK_INCOMPLETE" | "WORK_REVIEW_REQUIRED";
export type CaptureVerificationQuery = {
  captureId: string;
  offset: number;
  limit: number;
  maxAgeMinutes: number;
  includeResolved: boolean;
};
export type CaptureVerificationRow = {
  taskId: string;
  externalTaskId: string;
  title: string;
  severity: string;
  disposition: string;
  required: boolean;
  gap: CaptureVerificationGap;
  providerCheckId: string | null;
  providerEvidenceId: string | null;
  providerOutcome: string | null;
  checkedAt: string | null;
  workItemIds: string[];
  workReadiness: Array<{
    workItemId: string;
    state: ReadinessState;
    canRequestHumanReview: boolean;
  }>;
  reasons: string[];
};
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Invalid capture verification query.");
  return value as Record<string, unknown>;
}
function integer(value: unknown, label: string, min: number, max: number) {
  if (typeof value !== "number" || !Number.isSafeInteger(value) ||
      value < min || value > max)
    throw new WorkInputError("INVALID", "Invalid " + label + ".");
  return value;
}
export function parseCaptureVerificationQuery(
  value: unknown,
): CaptureVerificationQuery {
  const raw = object(value);
  if (Object.keys(raw).some(key => ![
    "captureId", "offset", "limit", "maxAgeMinutes", "includeResolved",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown capture verification filter.");
  if (raw.includeResolved !== undefined &&
      typeof raw.includeResolved !== "boolean")
    throw new WorkInputError("INVALID", "Invalid resolved filter.");
  return {
    captureId: parseWorkId(raw.captureId, "capture ID"),
    offset: integer(raw.offset ?? 0, "offset", 0, 1000000),
    limit: integer(raw.limit ?? 50, "limit", 1, 100),
    maxAgeMinutes: integer(raw.maxAgeMinutes ?? 60,
      "maximum age", 1, 1440),
    includeResolved: raw.includeResolved === true,
  };
}
type Task = {
  id: string; externalTaskId: string; title: string;
  severity: string; disposition: string; required: boolean;
};
type Check = {
  id: string; taskId: string; evidenceId: string;
  provider: string; controlId: string; outcome: string;
  checkedAt: Date; observationDigest: string;
  failureCode: string | null;
};
type Evidence = {
  id: string; organizationId: string; source: string;
  domain: string; controlId: string; scope: string;
  state: string; schemaVersion: number;
  observedAt: Date | null; updatedAt: Date; details: unknown;
};
type Link = {
  taskId: string; workItemId: string;
  unlinkedAt: Date | null;
  workItem: {
    status: string;
    remediation: { status: string };
    finding: { status: string };
    evidenceLinks: Array<{ evidenceId: string }>;
  };
};
export function classifyCaptureVerification(
  task: Task,
  latestCheck: Check | null,
  evidence: Evidence | null,
  links: Link[],
  allChecks: Check[],
  allEvidence: Evidence[],
  now: Date,
  maxAgeMinutes: number,
): CaptureVerificationRow {
  const gate = evaluateTechnicalGate(
    task.id, latestCheck, evidence, now, maxAgeMinutes);
  const workReadiness = links.map(link => {
    const record: WorkReadinessRecord = {
      taskId: task.id, workItemId: link.workItemId,
      unlinkedAt: link.unlinkedAt,
      reviewDisposition: task.disposition,
      workStatus: link.workItem.status,
      remediationStatus: link.workItem.remediation.status,
      findingStatus: link.workItem.finding.status,
      evidenceIds: link.workItem.evidenceLinks.map(x => x.evidenceId),
    };
    const result = evaluateWorkReadiness(
      record, allChecks.filter(x => x.taskId === task.id),
      allEvidence, now, maxAgeMinutes);
    return {
      workItemId: link.workItemId,
      state: result.state,
      canRequestHumanReview: result.canRequestHumanReview,
    };
  });
  let gap: CaptureVerificationGap;
  const reasons = [gate.reason];
  switch (gate.gate) {
    case "NO_CHECK":
      gap = "NO_PROVIDER_CHECK";
      break;
    case "PROVIDER_ERROR":
      gap = "PROVIDER_ERROR";
      break;
    case "FAILED":
      gap = "PROVIDER_FAILED";
      break;
    case "INCONCLUSIVE":
      gap = "PROVIDER_INCONCLUSIVE";
      break;
    case "EXPIRED":
      gap = "PROVIDER_EXPIRED";
      break;
    case "STALE":
      gap = "EVIDENCE_CHANGED";
      break;
    case "PROVIDER_PASS":
      gap = "PROVIDER_PASS";
      break;
  }
  if (!latestCheck && !links.length) {
    gap = "NO_EVIDENCE";
    reasons.push("No provider check or explicitly linked remediation work.");
  } else if (gate.sourceVerified && !links.length) {
    gap = "WORK_NOT_LINKED";
    reasons.push("The verified observation has no linked remediation work.");
  } else if (gate.sourceVerified && links.some(
    x => x.workItem.status !== "DONE")) {
    gap = "WORK_INCOMPLETE";
    reasons.push("One or more linked remediation work items are incomplete.");
  } else if (gate.sourceVerified && workReadiness.some(
    x => !x.canRequestHumanReview)) {
    gap = "WORK_REVIEW_REQUIRED";
    reasons.push("Provider verification is not sufficient for all linked work evidence.");
  }
  return {
    taskId: task.id, externalTaskId: task.externalTaskId,
    title: task.title, severity: task.severity,
    disposition: task.disposition, required: task.required,
    gap,
    providerCheckId: latestCheck?.id ?? null,
    providerEvidenceId: latestCheck?.evidenceId ?? null,
    providerOutcome: latestCheck?.outcome ?? null,
    checkedAt: latestCheck?.checkedAt.toISOString() ?? null,
    workItemIds: links.map(link => link.workItemId),
    workReadiness, reasons,
  };
}
export async function inspectCaptureVerificationGaps(
  scope: ReviewScope, value: unknown,
  now = new Date(),
) {
  if (!canReadWork(scope.role))
    throw new WorkInputError("FORBIDDEN", "Verification gap report denied.");
  const query = parseCaptureVerificationQuery(value);
  const capture = await db.integrityCaseCapture.findFirst({
    where: {
      id: query.captureId, organizationId: scope.organizationId,
    },
    select: {
      id: true, source: true, capturedAt: true,
      complete: true, digest: true,
    },
  });
  if (!capture)
    throw new WorkInputError("MISSING", "Capture not found.");
  const where = {
    organizationId: scope.organizationId,
    captureId: capture.id,
    ...(query.includeResolved ? {} : {
      disposition: { notIn: ["RESOLVED", "WAIVED"] as
        Array<"RESOLVED" | "WAIVED"> },
    }),
  };
  const [total, tasks] = await db.$transaction([
    db.integrityReviewTask.count({ where }),
    db.integrityReviewTask.findMany({
      where,
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      skip: query.offset, take: query.limit,
      select: {
        id: true, externalTaskId: true, title: true,
        severity: true, disposition: true, required: true,
      },
    }),
  ]);
  const taskIds = tasks.map(task => task.id);
  const [checks, links] = await Promise.all([
    taskIds.length ? db.integrityProviderCheck.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: taskIds },
      },
      orderBy: [{ checkedAt: "desc" }, { id: "desc" }],
      select: {
        id: true, taskId: true, evidenceId: true,
        provider: true, controlId: true, outcome: true,
        checkedAt: true, observationDigest: true, failureCode: true,
      },
    }) : Promise.resolve([]),
    taskIds.length ? db.integrityReviewWorkLink.findMany({
      where: {
        organizationId: scope.organizationId,
        taskId: { in: taskIds },
        unlinkedAt: null,
      },
      select: {
        taskId: true, workItemId: true, unlinkedAt: true,
        workItem: {
          select: {
            status: true,
            remediation: { select: { status: true } },
            finding: { select: { status: true } },
            evidenceLinks: {
              where: { unlinkedAt: null },
              select: { evidenceId: true },
            },
          },
        },
      },
    }) : Promise.resolve([]),
  ]);
  const evidenceIds = [...new Set([
    ...checks.map(check => check.evidenceId),
    ...links.flatMap(link => link.workItem.evidenceLinks.map(x => x.evidenceId)),
  ])];
  const evidence = evidenceIds.length ? await db.securityEvidence.findMany({
    where: {
      organizationId: scope.organizationId,
      id: { in: evidenceIds },
    },
  }) : [];
  const evidenceById = new Map(evidence.map(x => [x.id, x]));
  const latestByTask = new Map<string, typeof checks[number]>();
  for (const check of checks) {
    if (!latestByTask.has(check.taskId))
      latestByTask.set(check.taskId, check);
  }
  const linksByTask = new Map<string, typeof links>();
  for (const link of links) {
    const group = linksByTask.get(link.taskId) ?? [];
    group.push(link);
    linksByTask.set(link.taskId, group);
  }
  const rows = tasks.map(task => {
    const check = latestByTask.get(task.id) ?? null;
    return classifyCaptureVerification(
      task, check,
      check ? evidenceById.get(check.evidenceId) ?? null : null,
      linksByTask.get(task.id) ?? [],
      checks, evidence, now, query.maxAgeMinutes,
    );
  });
  const summary: Record<CaptureVerificationGap, number> = {
    NO_EVIDENCE: 0, NO_PROVIDER_CHECK: 0,
    PROVIDER_ERROR: 0, PROVIDER_FAILED: 0,
    PROVIDER_INCONCLUSIVE: 0, PROVIDER_EXPIRED: 0,
    EVIDENCE_CHANGED: 0, PROVIDER_PASS: 0,
    WORK_NOT_LINKED: 0, WORK_INCOMPLETE: 0,
    WORK_REVIEW_REQUIRED: 0,
  };
  for (const row of rows) summary[row.gap]++;
  return {
    capture, total, offset: query.offset, limit: query.limit,
    hasMore: query.offset + rows.length < total,
    rows, summary,
    limitations: [
      "This report is read-only and is not a security re-scan.",
      "Provider checks are evaluated at their original timestamps.",
      "Only explicitly persisted associations are used for remediation readiness.",
      "Counts apply to the selected page, not necessarily the whole capture.",
      "No automatic review resolution, remediation verification or CyberScore change.",
    ],
  };
}
