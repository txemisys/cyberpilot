import { WorkInputError } from "./remediation-work-input";
import {
  linkIntegrityCaseToWork, unlinkIntegrityCaseFromWork,
  listCompleteIntegrityWorkLinkState,
  type IntegrityWorkLinkScope,
  type IntegrityLinkHistoryEvent,
} from "./work-integrity-evidence-links";
import {
  parseIntegrityPlanRequest, planIntegrityLinkOperations,
  type IntegrityPlanRequest, type IntegrityPlanDecision,
  type IntegrityPlanExecutionOutcome, type IntegrityPlanExecutionReport,
  summarizeIntegrityExecution,
} from "./work-integrity-link-plan";

export type IntegrityBatchExecutionMode = "STOP_ON_ERROR" | "CONTINUE_ON_ERROR";
export type IntegrityBatchExecutionRequest = IntegrityPlanRequest & {
  mode?: IntegrityBatchExecutionMode;
};
export type IntegrityBatchExecutionResult = IntegrityPlanExecutionReport & {
  mode: IntegrityBatchExecutionMode;
  startedAt: string;
  finishedAt: string;
  initialEventCount: number;
  finalEventCount: number;
  stoppedEarly: boolean;
  warnings: string[];
};
export type IntegrityBatchExecutor = {
  readHistory: (organizationId: string, captureId: string) =>
    Promise<{ events: IntegrityLinkHistoryEvent[] }>;
  link: typeof linkIntegrityCaseToWork;
  unlink: typeof unlinkIntegrityCaseFromWork;
};
const defaultExecutor: IntegrityBatchExecutor = {
  readHistory: listCompleteIntegrityWorkLinkState,
  link: linkIntegrityCaseToWork,
  unlink: unlinkIntegrityCaseFromWork,
};
export function parseIntegrityBatchExecutionRequest(value: unknown): IntegrityBatchExecutionRequest {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Batch execution request must be an object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(key => ![
    "captureId", "operations", "expectedEventCount", "strict", "mode",
  ].includes(key)))
    throw new WorkInputError("INVALID", "Unknown batch execution field.");
  const { mode, ...request } = raw;
  if (mode !== undefined && mode !== "STOP_ON_ERROR" && mode !== "CONTINUE_ON_ERROR")
    throw new WorkInputError("INVALID", "Unknown batch execution mode.");
  return {
    ...parseIntegrityPlanRequest(request),
    mode: (mode ?? "STOP_ON_ERROR") as IntegrityBatchExecutionMode,
  };
}
function failed(operationId: string, error: unknown): IntegrityPlanExecutionOutcome {
  if (error instanceof WorkInputError)
    return {
      operationId, status: "FAILED", auditId: null,
      errorCode: error.code, message: error.message,
    };
  return {
    operationId, status: "FAILED", auditId: null,
    errorCode: "INTERNAL", message: "Unable to apply integrity operation.",
  };
}
function skipped(item: IntegrityPlanDecision): IntegrityPlanExecutionOutcome {
  return {
    operationId: item.operationId, status: "SKIPPED",
    auditId: null, errorCode: item.code, message: item.message,
  };
}
function rejected(item: IntegrityPlanDecision): IntegrityPlanExecutionOutcome {
  return {
    operationId: item.operationId, status: "FAILED",
    auditId: null, errorCode: item.code, message: item.message,
  };
}
function ensureScope(scope: IntegrityWorkLinkScope) {
  if (!scope.organizationId || !scope.actorUserId ||
      (scope.role !== "OWNER" && scope.role !== "ADMIN"))
    throw new WorkInputError("FORBIDDEN", "Organization administrator required.");
}
export async function executeIntegrityBatch(
  scope: IntegrityWorkLinkScope,
  value: unknown,
  executor: IntegrityBatchExecutor = defaultExecutor,
): Promise<IntegrityBatchExecutionResult> {
  ensureScope(scope);
  const request = parseIntegrityBatchExecutionRequest(value);
  const mode = request.mode ?? "STOP_ON_ERROR";
  const startedAt = new Date().toISOString();
  const initial = await executor.readHistory(scope.organizationId, request.captureId);
  const plan = planIntegrityLinkOperations(request, initial.events);
  const warnings: string[] = [];
  if (!plan.executable)
    throw new WorkInputError("CONFLICT", "Batch plan contains rejected operations.");
  const outcomes: IntegrityPlanExecutionOutcome[] = [];
  let stoppedEarly = false;
  for (const item of plan.decisions) {
    if (!item.executable) {
      outcomes.push(skipped(item));
      continue;
    }
    if (stoppedEarly) {
      outcomes.push({
        operationId: item.operationId, status: "FAILED",
        auditId: null, errorCode: "NOT_EXECUTED",
        message: "Execution stopped after an earlier error.",
      });
      continue;
    }
    try {
      // Re-read before each mutation: a previous operation or another writer
      // may have changed the audit stream since the initial dry run.
      const current = await executor.readHistory(scope.organizationId, request.captureId);
      const original = request.operations.find(x => x.operationId === item.operationId)!;
      const fresh = planIntegrityLinkOperations({
        captureId: request.captureId,
        operations: [original],
        strict: request.strict,
      }, current.events);
      const latest = fresh.decisions[0]!;
      if (!latest.executable) {
        if (latest.code === "ALREADY_LINKED" || latest.code === "ALREADY_WITHDRAWN") {
          outcomes.push({
            operationId: item.operationId, status: "FAILED", auditId: null,
            errorCode: "CONCURRENT_CHANGE",
            message: "Association state changed after initial planning.",
          });
          if (mode === "STOP_ON_ERROR") stoppedEarly = true;
          continue;
        }
        throw new WorkInputError("CONFLICT", latest.message);
      }
      if (original.action === "LINK") {
        const result = await executor.link(scope, {
          captureId: request.captureId,
          caseKey: original.caseKey,
          workItemId: original.workItemId,
        });
        outcomes.push({
          operationId: item.operationId, status: "APPLIED",
          auditId: result.auditId, errorCode: null, message: null,
        });
      } else {
        const result = await executor.unlink(scope, { auditId: original.auditId });
        outcomes.push({
          operationId: item.operationId, status: "APPLIED",
          auditId: result.auditId, errorCode: null, message: null,
        });
      }
    } catch (error) {
      outcomes.push(failed(item.operationId, error));
      if (mode === "STOP_ON_ERROR") stoppedEarly = true;
    }
  }
  const final = await executor.readHistory(scope.organizationId, request.captureId);
  const summary = summarizeIntegrityExecution(plan, outcomes);
  if (summary.failed > 0)
    warnings.push("Some operations were not applied; successful mutations were retained.");
  if (final.events.length < initial.events.length)
    warnings.push("Audit history shrank during execution; inspect retention and consistency.");
  return {
    ...summary, mode, startedAt, finishedAt: new Date().toISOString(),
    initialEventCount: initial.events.length,
    finalEventCount: final.events.length,
    stoppedEarly, warnings,
  };
}
