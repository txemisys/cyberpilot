import { db, type Prisma } from "@cyberpilot/database";
import {
  BASELINE_IG1_QUESTIONS,
  type BaselineSubmission, type BaselineResponse,
  validateBaselineSubmission, assessBaselineOfflineV2,
  verifyBaselineOfflineV2, buildBaselineReportV2,
  verifyBaselineReportV2, buildBaselineActionPlanV2,
  sha256V2, canonicalV2,
} from "@cyberpilot/risk-engine";

/** A tenant-scoped, compare-and-swap revision store; no technical security claims. */
export type BaselinePrincipal = {
  organizationId: string; userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type BaselineCommand = {
  operation: "READ" | "SAVE" | "SUBMIT" | "REOPEN" |
    "HISTORY" | "REVISION" | "COMPARE";
  expectedRevision?: number;
  responses?: BaselineResponse[];
  revision?: number; earlierRevision?: number;
  limit?: number;
};
export type BaselineDraftView = {
  organizationId: string;
  questionnaireVersion: 1;
  revision: number;
  state: "DRAFT" | "SUBMITTED";
  answers: BaselineResponse[];
  answered: number;
  unanswered: number;
  completePercent: number;
  responsesDigest: string;
  updatedAt: string;
  submittedAt: string | null;
  technicalScore: null;
  certifiedCIS: false;
  verifiedControls: 0;
};
export type BaselineMutationResult = {
  schema: "cyberpilot.baseline.persistence.v1";
  organizationId: string;
  operation: BaselineCommand["operation"];
  data: unknown;
  storedRawNotes: false;
  securityActionsExecuted: 0;
  v1CyberScoreUpdated: false;
  externalApprovalInferred: false;
};
export class BaselineConflictError extends Error {
  constructor() {
    super("Baseline revision conflict. Reload the latest revision before saving.");
  }
}
function fail(message: string): never {
  throw new Error("Baseline storage: " + message);
}
function digest(value: unknown) {
  return sha256V2(canonicalV2(value));
}
function json(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}
function safeInt(value: unknown, min: number, max: number) {
  if (!Number.isSafeInteger(value) ||
      typeof value !== "number" || value < min || value > max)
    fail("Invalid integer parameter.");
  return value;
}
const validAnswers = new Set([
  "YES", "NO", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE",
]);
const validIds = new Set(BASELINE_IG1_QUESTIONS.map(x => x.id));
function cleanAnswers(input: unknown): BaselineResponse[] {
  if (!Array.isArray(input) ||
      input.length > BASELINE_IG1_QUESTIONS.length)
    fail("Invalid questionnaire length.");
  const seen = new Set<string>();
  const sanitized: BaselineResponse[] = [];
  for (const item of input) {
    if (!item || typeof item !== "object" ||
        Array.isArray(item))
      fail("Invalid response row.");
    const row = item as Record<string, unknown>;
    if (!validIds.has(String(row.questionId)) ||
        !validAnswers.has(String(row.answer)) ||
        seen.has(String(row.questionId)))
      fail("Unknown, repeated or unsupported control answer.");
    if (Object.keys(row).some(x =>
      !["questionId", "answer", "evidenceReference", "notes"].includes(x)))
      fail("Extra questionnaire fields are not accepted.");
    seen.add(String(row.questionId));
    const reference = row.evidenceReference;
    if (reference !== undefined && reference !== null &&
        (typeof reference !== "string" ||
         !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,95}$/.test(reference)))
      fail("Evidence references must be opaque IDs, not URLs or secrets.");
    if (row.notes !== undefined && row.notes !== null &&
        typeof row.notes !== "string")
      fail("Invalid notes type.");
    sanitized.push({
      questionId: String(row.questionId),
      answer: row.answer as BaselineResponse["answer"],
      evidenceReference: reference as string | null ?? null,
      // No raw notes are persisted or exported.
      notes: null,
    });
  }
  sanitized.sort((a, b) => a.questionId.localeCompare(b.questionId));
  return sanitized;
}
function submission(organizationId: string,
  responses: BaselineResponse[], when: string):
  BaselineSubmission {
  return {
    organizationId, questionnaireVersion: 1,
    submittedAt: when, responses,
  };
}
function verifyResponses(organizationId: string,
  responses: BaselineResponse[], at: string) {
  const checked = validateBaselineSubmission(
    submission(organizationId, responses, at), organizationId);
  if (!checked.valid)
    fail("Responses rejected: " + checked.errors.join(","));
}
function view(row: {
  organizationId: string; questionnaireVersion: number;
  revision: number; status: string;
  responses: unknown; responsesDigest: string;
  updatedAt: Date; submittedAt: Date | null;
}): BaselineDraftView {
  const responses = cleanAnswers(row.responses);
  if (row.questionnaireVersion !== 1 ||
      !["DRAFT", "SUBMITTED"].includes(row.status) ||
      row.responsesDigest !== digest(responses))
    fail("Stored draft integrity failed.");
  return {
    organizationId: row.organizationId,
    questionnaireVersion: 1,
    revision: row.revision,
    state: row.status as BaselineDraftView["state"],
    answers: responses,
    answered: responses.length,
    unanswered: BASELINE_IG1_QUESTIONS.length - responses.length,
    completePercent: Math.round(100 * responses.length /
      BASELINE_IG1_QUESTIONS.length),
    responsesDigest: row.responsesDigest,
    updatedAt: row.updatedAt.toISOString(),
    submittedAt: row.submittedAt?.toISOString() ?? null,
    technicalScore: null, certifiedCIS: false, verifiedControls: 0,
  };
}
async function authorize(
  principal: BaselinePrincipal, write: boolean,
) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(
      principal.organizationId) ||
      !/^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(principal.userId))
    fail("Invalid actor or organization.");
  const membership = await db.membership.findFirst({
    where: { organizationId: principal.organizationId,
      userId: principal.userId },
    select: { role: true },
  });
  if (!membership || membership.role !== principal.role)
    fail("Current organization membership required.");
  if (write && !["OWNER", "ADMIN", "MEMBER"].includes(
      membership.role))
    fail("Auditors cannot modify organizational declarations.");
}
function parseCommand(raw: unknown): BaselineCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected command object.");
  const record = raw as Record<string, unknown>;
  const allowed = [
    "operation", "responses", "expectedRevision",
    "revision", "earlierRevision", "limit",
  ];
  if (Object.keys(record).some(key => !allowed.includes(key)))
    fail("Unsupported command field.");
  const operations: BaselineCommand["operation"][] = [
    "READ","SAVE","SUBMIT","REOPEN","HISTORY","REVISION","COMPARE",
  ];
  if (!operations.includes(record.operation as BaselineCommand["operation"]))
    fail("Unknown operation.");
  const command: BaselineCommand = {
    operation: record.operation as BaselineCommand["operation"],
  };
  if (record.expectedRevision !== undefined)
    command.expectedRevision = safeInt(record.expectedRevision, 0, 10000000);
  if (record.revision !== undefined)
    command.revision = safeInt(record.revision, 1, 10000000);
  if (record.earlierRevision !== undefined)
    command.earlierRevision = safeInt(record.earlierRevision, 1, 10000000);
  if (record.limit !== undefined)
    command.limit = safeInt(record.limit, 1, 100);
  if (record.responses !== undefined)
    command.responses = cleanAnswers(record.responses);
  if (["SAVE","SUBMIT","REOPEN"].includes(command.operation) &&
      command.expectedRevision === undefined)
    fail("Optimistic expectedRevision is required.");
  if (["SAVE","SUBMIT"].includes(command.operation) &&
      !command.responses)
    fail("Response array is required.");
  return command;
}
async function recordAudit(tx: Prisma.TransactionClient,
  principal: BaselinePrincipal, draftId: string,
  revision: number, kind: string, responsesDigest: string) {
  await tx.auditEvent.create({
    data: {
      organizationId: principal.organizationId,
      actorType: "USER", actorUserId: principal.userId,
      action: "BASELINE_" + kind,
      resourceType: "BASELINE_DRAFT",
      resourceId: draftId,
      metadata: {
        questionnaireVersion: 1, revision,
        responsesDigest, storedNotes: false,
        thirdPartyAuthentication: false,
        securityCertification: false,
        legacyScoreWrites: 0,
      },
    },
  });
}
export class BaselinePersistenceService {
  async execute(principal: BaselinePrincipal,
    raw: unknown): Promise<BaselineMutationResult> {
    const command = parseCommand(raw);
    const write = ["SAVE", "SUBMIT", "REOPEN"].includes(command.operation);
    await authorize(principal, write);
    const data = await this.dispatch(principal, command);
    return {
      schema: "cyberpilot.baseline.persistence.v1",
      organizationId: principal.organizationId,
      operation: command.operation, data,
      storedRawNotes: false, securityActionsExecuted: 0,
      v1CyberScoreUpdated: false, externalApprovalInferred: false,
    };
  }
  private async dispatch(principal: BaselinePrincipal,
    command: BaselineCommand): Promise<unknown> {
    const organizationId = principal.organizationId;
    if (command.operation === "READ") {
      const draft = await db.baselineDraft.findUnique({
        where: { organizationId_questionnaireVersion: {
          organizationId, questionnaireVersion: 1,
        } },
      });
      return draft ? { exists: true, draft: view(draft) } :
        { exists: false, draft: null, revision: 0 };
    }
    if (command.operation === "HISTORY") {
      const rows = await db.baselineRevision.findMany({
        where: { organizationId },
        orderBy: { revision: "desc" },
        take: command.limit ?? 30,
      });
      return {
        revisions: rows.map(x => ({
          revision: x.revision, eventKind: x.eventKind,
          digest: x.responsesDigest,
          assessmentDigest: x.assessmentDigest,
          reportDigest: x.reportDigest,
          actorId: x.actorUserId,
          createdAt: x.createdAt.toISOString(),
          technicalProof: false,
          certification: false,
        })),
        v1ScoresQueried: false,
      };
    }
    if (command.operation === "REVISION" ||
        command.operation === "COMPARE") {
      if (!command.revision)
        fail("Specify a revision to read.");
      const current = await db.baselineRevision.findFirst({
        where: { organizationId, revision: command.revision },
      });
      if (!current) fail("Requested revision does not exist.");
      const currentAnswers = cleanAnswers(current.responses);
      if (digest(currentAnswers) !== current.responsesDigest)
        fail("Historical revision digest mismatch.");
      if (command.operation === "REVISION")
        return {
          revision: current.revision,
          responses: currentAnswers,
          digest: current.responsesDigest,
          report: current.report,
          originalScoreModified: false,
        };
      if (!command.earlierRevision ||
          command.earlierRevision >= command.revision)
        fail("Comparison requires an earlier revision.");
      const older = await db.baselineRevision.findFirst({
        where: { organizationId,
          revision: command.earlierRevision },
      });
      if (!older) fail("Earlier revision not found.");
      const previous = cleanAnswers(older.responses);
      if (digest(previous) !== older.responsesDigest)
        fail("Historical baseline source integrity failure.");
      const oldMap = new Map(previous.map(x => [x.questionId, x.answer]));
      const newMap = new Map(currentAnswers.map(x => [x.questionId, x.answer]));
      return {
        olderRevision: older.revision, newerRevision: current.revision,
        priorDigest: older.responsesDigest,
        currentDigest: current.responsesDigest,
        changed: [...validIds].filter(id =>
          oldMap.get(id) !== newMap.get(id)).map(id => ({
          questionId: id, before: oldMap.get(id) ?? "UNANSWERED",
          after: newMap.get(id) ?? "UNANSWERED",
          independentlyVerified: false,
        })),
        completionDelta: currentAnswers.length - previous.length,
        remediationProven: false,
        historicalCyberScoreModified: false,
      };
    }
    return db.$transaction(async tx => {
      const previous = await tx.baselineDraft.findUnique({
        where: { organizationId_questionnaireVersion: {
          organizationId, questionnaireVersion: 1,
        } },
      });
      const expected = command.expectedRevision!;
      if ((!previous && expected !== 0) ||
          (previous && previous.revision !== expected))
        throw new BaselineConflictError();
      if (command.operation === "REOPEN" &&
          (!previous || previous.status !== "SUBMITTED"))
        fail("Only a submitted Baseline can be reopened.");
      if (command.operation !== "REOPEN" &&
          previous?.status === "SUBMITTED")
        fail("Reopen a submitted assessment before editing.");
      const now = new Date();
      const answers = command.operation === "REOPEN" ?
        cleanAnswers(previous!.responses) : command.responses!;
      verifyResponses(organizationId, answers, now.toISOString());
      const revision = expected + 1;
      const status = command.operation === "SUBMIT" ?
        "SUBMITTED" : "DRAFT";
      const responsesDigest = digest(answers);
      const assessment = command.operation === "SUBMIT" ?
        assessBaselineOfflineV2(submission(
          organizationId, answers, now.toISOString()), {
          organizationId,
          snapshotId: "baseline-" + sha256V2(
            organizationId + ":" + revision + ":" + responsesDigest)
            .slice(0, 24),
          evaluatedAt: now.toISOString(),
          completedBy: principal.userId,
          notePolicy: "DISCARD_CONTENT",
          referencePolicy: "OPAQUE_IDENTIFIERS_ONLY",
          maxActions: 100,
        }) : null;
      const report = assessment ? buildBaselineReportV2(assessment) : null;
      if (assessment && (!verifyBaselineOfflineV2(assessment).valid ||
          !report || !verifyBaselineReportV2(report, assessment).valid ||
          report.summary.securityScore !== null))
        fail("Invalid submitted baseline assessment.");
      const data = {
        revision, status, responses: json(answers),
        responsesDigest, updatedById: principal.userId,
        submittedAt: status === "SUBMITTED" ? now : null,
      };
      const saved = previous ?
        await tx.baselineDraft.update({
          where: { id: previous.id, revision: expected },
          data,
        }) :
        await tx.baselineDraft.create({
          data: {
            organizationId, questionnaireVersion: 1,
            createdById: principal.userId, ...data,
          },
        });
      await tx.baselineRevision.create({
        data: {
          organizationId, draftId: saved.id,
          revision, eventKind: command.operation,
          questionnaireVersion: 1, responses: json(answers),
          responsesDigest,
          assessmentDigest: assessment?.digest ?? null,
          reportDigest: report?.digest ?? null,
          ...(assessment ? { assessment: json(assessment) } : {}),
          ...(report ? { report: json(report) } : {}),
          actorUserId: principal.userId,
        },
      });
      await recordAudit(tx, principal, saved.id, revision,
        command.operation, responsesDigest);
      return {
        draft: view(saved), created: !previous,
        report, actionPlan: report ?
          buildBaselineActionPlanV2(report) : null,
        historyRevision: revision,
        auditWritten: true,
        legacyScoreWrites: 0,
      };
    }, { isolationLevel: "Serializable" });
  }
}
