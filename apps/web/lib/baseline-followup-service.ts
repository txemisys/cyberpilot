import { db, type Prisma } from "@cyberpilot/database";
import { buildBaselineFollowUpExecutive,
  exportBaselineFollowUpExecutive,
} from "./baseline-followup-report";
import {
  buildBaselineActionPlanV2, verifyBaselineReportV2,
  type BaselineReportV2,
  sha256V2, canonicalV2,
} from "@cyberpilot/risk-engine";

/** Separate operations workflow. A reported completion is not verified remediation. */
export type BaselineFollowUpScope = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type BaselineFollowUpStatus =
  "OPEN" | "IN_PROGRESS" | "BLOCKED" |
    "COMPLETED_REPORTED" | "REOPENED";
export type BaselineFollowUpCommand = {
  operation: "INITIALIZE" | "LIST" | "READ" |
    "UPDATE" | "HISTORY" | "SUMMARY" | "REPORT" | "EXPORT";
  questionId?: string;
  expectedRevision?: number;
  status?: BaselineFollowUpStatus;
  ownerUserId?: string | null;
  dueAt?: string | null;
  evidenceReference?: string | null;
  limit?: number;
  format?: "JSON" | "CSV" | "MARKDOWN";
};
export type BaselineFollowUpView = {
  id: string;
  organizationId: string;
  questionId: string;
  questionnaireVersion: 1;
  sourceDraftRevision: number;
  revision: number;
  severity: string;
  status: BaselineFollowUpStatus;
  title: string;
  nextAction: string;
  evidenceNeeded: string;
  evidenceReference: string | null;
  ownerUserId: string | null;
  dueAt: string | null;
  completedAt: string | null;
  createdAt: string;
  updatedAt: string;
  independentlyVerified: false;
  securityCertified: false;
  historicalCyberScoreModified: false;
};
export type BaselineFollowUpResponse = {
  schema: "cyberpilot.baseline.followup.service.v1";
  organizationId: string;
  operation: BaselineFollowUpCommand["operation"];
  data: unknown;
  externalActionsExecuted: 0;
  independentRemediationVerified: false;
  customerSecurityCertified: false;
  legacyCyberScoreChanged: false;
};
export class BaselineFollowUpConflict extends Error {
  constructor() {
    super("The follow-up revision changed; reload before updating.");
  }
}
const statuses: BaselineFollowUpStatus[] = [
  "OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED_REPORTED", "REOPENED",
];
const transitions: Record<BaselineFollowUpStatus, BaselineFollowUpStatus[]> = {
  OPEN: ["IN_PROGRESS", "BLOCKED", "COMPLETED_REPORTED"],
  IN_PROGRESS: ["OPEN", "BLOCKED", "COMPLETED_REPORTED"],
  BLOCKED: ["OPEN", "IN_PROGRESS"],
  COMPLETED_REPORTED: ["REOPENED"],
  REOPENED: ["OPEN", "IN_PROGRESS", "BLOCKED", "COMPLETED_REPORTED"],
};
function fail(detail: string): never {
  throw Error("Baseline follow-up: " + detail);
}
function validId(id: unknown) {
  return typeof id === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(id);
}
function date(raw: unknown) {
  return typeof raw === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(raw) &&
    Number.isFinite(Date.parse(raw)) &&
    new Date(raw).toISOString() === raw;
}
function parse(raw: unknown): BaselineFollowUpCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected request object.");
  const x = raw as Record<string, unknown>;
  const allowed = [
    "operation", "questionId", "expectedRevision",
    "status", "ownerUserId", "dueAt", "evidenceReference", "limit", "format",
  ];
  if (Object.keys(x).some(key => !allowed.includes(key)))
    fail("Unknown command field.");
  const operations: BaselineFollowUpCommand["operation"][] = [
    "INITIALIZE","LIST","READ","UPDATE","HISTORY","SUMMARY",
    "REPORT","EXPORT",
  ];
  if (!operations.includes(x.operation as BaselineFollowUpCommand["operation"]))
    fail("Unsupported follow-up operation.");
  const command: BaselineFollowUpCommand = {
    operation: x.operation as BaselineFollowUpCommand["operation"],
  };
  if (x.questionId !== undefined) {
    if (typeof x.questionId !== "string" ||
        !/^[a-z][a-z0-9-]{2,79}$/.test(x.questionId))
      fail("Invalid question identifier.");
    command.questionId = x.questionId;
  }
  if (x.expectedRevision !== undefined) {
    if (typeof x.expectedRevision !== "number" ||
        !Number.isSafeInteger(x.expectedRevision) ||
        x.expectedRevision < 1 || x.expectedRevision > 1e7)
      fail("Invalid optimistic revision.");
    command.expectedRevision = x.expectedRevision;
  }
  if (x.status !== undefined) {
    if (!statuses.includes(x.status as BaselineFollowUpStatus))
      fail("Unknown follow-up status.");
    command.status = x.status as BaselineFollowUpStatus;
  }
  if (x.ownerUserId !== undefined) {
    if (x.ownerUserId !== null && !validId(x.ownerUserId))
      fail("Owner must be a current organization user.");
    command.ownerUserId = x.ownerUserId as string | null;
  }
  if (x.dueAt !== undefined) {
    if (x.dueAt !== null && !date(x.dueAt))
      fail("Invalid deadline timestamp.");
    command.dueAt = x.dueAt as string | null;
  }
  if (x.evidenceReference !== undefined) {
    if (x.evidenceReference !== null &&
        (typeof x.evidenceReference !== "string" ||
        !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,95}$/.test(x.evidenceReference)))
      fail("Evidence must be an opaque reference, not a URL or credential.");
    command.evidenceReference = x.evidenceReference as string | null;
  }
  if (x.format !== undefined) {
    if (!["JSON", "CSV", "MARKDOWN"].includes(String(x.format)))
      fail("Unsupported export format.");
    command.format = x.format as "JSON" | "CSV" | "MARKDOWN";
  }
  if (x.limit !== undefined) {
    if (typeof x.limit !== "number" ||
        !Number.isSafeInteger(x.limit) ||
        x.limit < 1 || x.limit > 100)
      fail("Invalid page capacity.");
    command.limit = x.limit;
  }
  if (["READ","UPDATE","HISTORY"].includes(command.operation) &&
      !command.questionId)
    fail("Select a Baseline question.");
  if (command.operation === "UPDATE" && !command.expectedRevision)
    fail("Expected revision is mandatory.");
  return command;
}
function view(row: {
  id: string; organizationId: string;
  questionId: string; questionnaireVersion: number;
  sourceDraftRevision: number;
  revision: number; severity: string; status: string;
  title: string; nextAction: string; evidenceNeeded: string;
  evidenceReference: string | null; ownerUserId: string | null;
  dueAt: Date | null; completedAt: Date | null;
  createdAt: Date; updatedAt: Date;
}): BaselineFollowUpView {
  if (row.questionnaireVersion !== 1 ||
      !statuses.includes(row.status as BaselineFollowUpStatus))
    fail("Invalid stored action state.");
  return {
    id: row.id,
    organizationId: row.organizationId,
    questionId: row.questionId,
    questionnaireVersion: 1,
    sourceDraftRevision: row.sourceDraftRevision,
    revision: row.revision, severity: row.severity,
    status: row.status as BaselineFollowUpStatus,
    title: row.title, nextAction: row.nextAction,
    evidenceNeeded: row.evidenceNeeded,
    evidenceReference: row.evidenceReference,
    ownerUserId: row.ownerUserId,
    dueAt: row.dueAt?.toISOString() ?? null,
    completedAt: row.completedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    independentlyVerified: false,
    securityCertified: false,
    historicalCyberScoreModified: false,
  };
}
async function authorize(actor: BaselineFollowUpScope,
  mutates: boolean) {
  if (!validId(actor.organizationId) || !validId(actor.userId))
    fail("Invalid actor or organization.");
  const membership = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId, userId: actor.userId,
    }, select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("Current organization membership is required.");
  if (mutates && membership.role === "AUDITOR")
    fail("Auditors have read-only access.");
}
async function recordEvent(
  tx: Prisma.TransactionClient,
  actor: BaselineFollowUpScope,
  row: { id: string; questionId: string;
    revision: number; status: string;
    ownerUserId: string | null;
    dueAt: Date | null; evidenceReference: string | null },
  action: string, priorState: string,
) {
  await tx.baselineFollowUpEvent.create({
    data: {
      organizationId: actor.organizationId,
      followUpId: row.id, revision: row.revision,
      action, previousStatus: priorState,
      nextStatus: row.status, ownerUserId: row.ownerUserId,
      dueAt: row.dueAt,
      evidenceReference: row.evidenceReference,
      actorUserId: actor.userId,
    },
  });
  await tx.auditEvent.create({
    data: {
      organizationId: actor.organizationId,
      actorType: "USER", actorUserId: actor.userId,
      action: "BASELINE_FOLLOWUP_" + action,
      resourceType: "BASELINE_FOLLOWUP", resourceId: row.id,
      metadata: {
        questionId: row.questionId,
        revision: row.revision,
        priorState, newState: row.status,
        externallyVerified: false,
        customerCertification: false,
        automaticAccountWrites: 0,
        historicalScoreWrites: 0,
      },
    },
  });
}
async function target(actor: BaselineFollowUpScope,
  questionId: string) {
  const result = await db.baselineFollowUp.findFirst({
    where: {
      organizationId: actor.organizationId,
      questionId, questionnaireVersion: 1,
    },
  });
  if (!result) fail("Baseline follow-up item not found.");
  return result;
}
export class BaselineFollowUpService {
  async execute(actor: BaselineFollowUpScope,
    raw: unknown): Promise<BaselineFollowUpResponse> {
    const command = parse(raw);
    const mutates = ["INITIALIZE","UPDATE"].includes(command.operation);
    await authorize(actor, mutates);
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.baseline.followup.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation, data,
      externalActionsExecuted: 0,
      independentRemediationVerified: false,
      customerSecurityCertified: false,
      legacyCyberScoreChanged: false,
    };
  }
  private async dispatch(actor: BaselineFollowUpScope,
    cmd: BaselineFollowUpCommand): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (cmd.operation === "REPORT" || cmd.operation === "EXPORT") {
      const rows = await db.baselineFollowUp.findMany({
        where: { organizationId },
        orderBy: { questionId: "asc" },
      });
      const report = buildBaselineFollowUpExecutive(
        organizationId, rows.map(view), new Date().toISOString());
      if (cmd.operation === "REPORT")
        return { report, containsVerifiedRemediation: false };
      return exportBaselineFollowUpExecutive(
        report, cmd.format ?? "JSON");
    }
    if (cmd.operation === "LIST") {
      const rows = await db.baselineFollowUp.findMany({
        where: { organizationId },
        orderBy: [
          { dueAt: "asc" }, { updatedAt: "desc" },
        ], take: cmd.limit ?? 50,
      });
      return { items: rows.map(view), otherOrganizationsIncluded: false };
    }
    if (cmd.operation === "SUMMARY") {
      const rows = await db.baselineFollowUp.findMany({
        where: { organizationId },
        select: {
          status: true, severity: true, dueAt: true,
          ownerUserId: true, updatedAt: true,
        },
      });
      const now = new Date();
      const byState = Object.fromEntries(statuses.map(s => [
        s, rows.filter(x => x.status === s).length,
      ]));
      return {
        total: rows.length, byState,
        withoutOwner: rows.filter(x => !x.ownerUserId).length,
        overdue: rows.filter(x => x.dueAt &&
          x.dueAt < now &&
          x.status !== "COMPLETED_REPORTED").length,
        highPriority: rows.filter(x => x.severity === "CRITICAL" ||
          x.severity === "HIGH").length,
        technicallyVerifiedCompleted: 0,
        customerComplianceCertified: false,
        automaticRemediations: 0,
      };
    }
    if (cmd.operation === "READ")
      return { item: view(await target(actor, cmd.questionId!)) };
    if (cmd.operation === "HISTORY") {
      const item = await target(actor, cmd.questionId!);
      const events = await db.baselineFollowUpEvent.findMany({
        where: { organizationId, followUpId: item.id },
        orderBy: { revision: "desc" }, take: cmd.limit ?? 50,
      });
      return {
        item: view(item),
        events: events.map(x => ({
          revision: x.revision, action: x.action,
          previousStatus: x.previousStatus, nextStatus: x.nextStatus,
          ownerUserId: x.ownerUserId,
          dueAt: x.dueAt?.toISOString() ?? null,
          evidenceReference: x.evidenceReference,
          actorUserId: x.actorUserId,
          at: x.createdAt.toISOString(),
          independentlyVerified: false,
        })),
      };
    }
    if (cmd.operation === "INITIALIZE") {
      return db.$transaction(async tx => {
        const last = await tx.baselineDraft.findFirst({
          where: { organizationId, questionnaireVersion: 1 },
        });
        if (!last || last.status !== "SUBMITTED")
          fail("Submit the Baseline first to create follow-up work.");
        const revision = await tx.baselineRevision.findFirst({
          where: {
            organizationId, draftId: last.id,
            revision: last.revision,
          },
        });
        if (!revision?.report || !revision.reportDigest)
          fail("Submitted Baseline report not found.");
        const report = revision.report as BaselineReportV2;
        if (!verifyBaselineReportV2(report).valid ||
            report.organizationId !== organizationId ||
            report.digest !== revision.reportDigest ||
            report.summary.securityScore !== null)
          fail("Cannot create actions from an unverified or foreign report.");
        const plan = buildBaselineActionPlanV2(report);
        let created = 0, preserved = 0;
        const existing = await tx.baselineFollowUp.findMany({
          where: { organizationId },
          select: { questionId: true },
        });
        const existingIds = new Set(existing.map(x => x.questionId));
        for (const action of plan.prioritized) {
          if (existingIds.has(action.questionId)) {
            preserved++;
            continue;
          }
          const source = report.actions.find(x =>
            x.questionId === action.questionId);
          if (!source) fail("Missing action provenance.");
          const row = await tx.baselineFollowUp.create({
            data: {
              organizationId, questionnaireVersion: 1,
              questionId: action.questionId,
              sourceDraftRevision: last.revision,
              severity: source.priority, status: "OPEN",
              revision: 1, title: action.title.slice(0, 512),
              nextAction: action.guidance.join(" ").slice(0, 2048),
              evidenceNeeded: action.requiredEvidence.slice(0, 512),
              evidenceReference: source.evidenceReference,
              createdById: actor.userId,
              updatedById: actor.userId,
            },
          });
          await recordEvent(tx, actor, row,
            "INITIALIZE", "NOT_CREATED");
          existingIds.add(row.questionId);
          created++;
        }
        return {
          created, preserved,
          reportDigest: report.digest, sourceRevision: last.revision,
          noExistingActionOverwritten: true,
          technicalRemediationProven: false,
        };
      }, { isolationLevel: "Serializable" });
    }
    if (cmd.operation === "UPDATE") {
      const current = await target(actor, cmd.questionId!);
      if (current.revision !== cmd.expectedRevision)
        throw new BaselineFollowUpConflict();
      const state = cmd.status ?? current.status as BaselineFollowUpStatus;
      if (state !== current.status &&
          !transitions[current.status as BaselineFollowUpStatus].includes(state))
        fail("Disallowed follow-up lifecycle transition.");
      const nextOwner = cmd.ownerUserId === undefined ?
        current.ownerUserId : cmd.ownerUserId;
      if (nextOwner) {
        const member = await db.membership.findFirst({
          where: { organizationId, userId: nextOwner },
          select: { id: true },
        });
        if (!member) fail("Follow-up owner is not part of the organization.");
      }
      const dueAt = cmd.dueAt === undefined ?
        current.dueAt : cmd.dueAt ?
          new Date(cmd.dueAt) : null;
      const reference = cmd.evidenceReference === undefined ?
        current.evidenceReference : cmd.evidenceReference;
      return db.$transaction(async tx => {
        const saved = await tx.baselineFollowUp.update({
          where: { id: current.id, revision: cmd.expectedRevision! },
          data: {
            revision: current.revision + 1,
            status: state, ownerUserId: nextOwner,
            dueAt, evidenceReference: reference,
            completedAt: state === "COMPLETED_REPORTED" ?
              new Date() : null,
            updatedById: actor.userId,
          },
        });
        await recordEvent(tx, actor, saved,
          "UPDATE", current.status);
        return {
          item: view(saved),
          reportedCompletionOnly: state === "COMPLETED_REPORTED",
          independentlyValidated: false,
          auditWritten: true,
          externalActionsExecuted: 0,
        };
      }, { isolationLevel: "Serializable" });
    }
    throw Error("Unknown follow-up dispatch.");
  }
}
export function baselineFollowUpDigest(
  rows: readonly BaselineFollowUpView[],
) {
  const normalized = [...rows].sort((a, b) =>
    a.questionId.localeCompare(b.questionId));
  return {
    schema: "cyberpilot.baseline.followup.snapshot.v1" as const,
    count: normalized.length,
    organizationId: normalized[0]?.organizationId ?? null,
    digest: sha256V2(canonicalV2(normalized)),
    allCustomerVerified: false as const,
    externalActionsExecuted: 0 as const,
  };
}
