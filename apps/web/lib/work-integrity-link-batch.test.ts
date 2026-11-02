import { describe, expect, it, vi } from "vitest";
import { WorkInputError } from "./remediation-work-input";
import type { IntegrityLinkHistoryEvent } from "./work-integrity-evidence-links";
import {
  executeIntegrityBatch, parseIntegrityBatchExecutionRequest,
  type IntegrityBatchExecutor,
} from "./work-integrity-link-batch";

const scope = {
  organizationId: "organization-one", actorUserId: "user-one",
  role: "ADMIN" as const,
};
const createdAt = "2026-11-01T10:00:00.000Z";
function linkEvent(auditId: string, caseKey = "case-one", workItemId = "work-one"):
  IntegrityLinkHistoryEvent {
  return {
    auditId, originalAuditId: null, action: "LINK",
    captureId: "capture-one", caseKey, workItemId,
    actorUserId: "user-one", occurredAt: createdAt,
  };
}
function fakeExecutor(initial: IntegrityLinkHistoryEvent[] = []) {
  const events = [...initial];
  let sequence = 0;
  const executor: IntegrityBatchExecutor = {
    readHistory: vi.fn(async () => ({ events: [...events] })),
    link: vi.fn(async (_scope, value) => {
      const input = value as { captureId: string; caseKey: string; workItemId: string };
      sequence++;
      const auditId = "created-" + sequence;
      events.push(linkEvent(auditId, input.caseKey, input.workItemId));
      return {
        auditId, captureId: input.captureId, caseKey: input.caseKey,
        workItemId: input.workItemId, actorUserId: "user-one",
        occurredAt: createdAt,
      };
    }),
    unlink: vi.fn(async (_scope, value) => {
      const input = value as { auditId: string };
      sequence++;
      const auditId = "withdrawal-" + sequence;
      const original = events.find(x => x.auditId === input.auditId)!;
      events.push({
        ...original, auditId, originalAuditId: original.auditId,
        action: "UNLINK", occurredAt: "2026-11-02T10:00:00.000Z",
      });
      return { auditId, originalAuditId: input.auditId };
    }),
  };
  return { executor, events };
}
function request(operations: unknown[], mode?: string) {
  return { captureId: "capture-one", operations, ...(mode ? { mode } : {}) };
}
const add = (id: string, caseKey: string) => ({
  operationId: id, action: "LINK", caseKey, workItemId: "work-one",
});
const remove = (id: string, auditId: string) => ({
  operationId: id, action: "UNLINK", auditId,
});
describe("integrity bulk execution", () => {
  it("applies multiple associations and returns audit identifiers", async () => {
    const { executor, events } = fakeExecutor();
    const result = await executeIntegrityBatch(scope, request([
      add("operation-one", "case-one"),
      add("operation-two", "case-two"),
    ]), executor);
    expect(result).toMatchObject({
      applied: 2, failed: 0, skipped: 0,
      initialEventCount: 0, finalEventCount: 2,
    });
    expect(result.outcomes.map(x => x.auditId)).toEqual(["created-1", "created-2"]);
    expect(events).toHaveLength(2);
  });
  it("withdraws an existing association through the original audit ID", async () => {
    const { executor } = fakeExecutor([linkEvent("audit-one")]);
    const result = await executeIntegrityBatch(scope,
      request([remove("operation-one", "audit-one")]), executor);
    expect(result.applied).toBe(1);
    expect(result.finalEventCount).toBe(2);
  });
  it("skips associations that are already active", async () => {
    const { executor } = fakeExecutor([linkEvent("audit-one")]);
    const result = await executeIntegrityBatch(scope,
      request([add("operation-one", "case-one")]), executor);
    expect(result.skipped).toBe(1);
    expect(executor.link).not.toHaveBeenCalled();
  });
  it("rejects missing withdrawal targets before applying changes", async () => {
    const { executor } = fakeExecutor();
    await expect(executeIntegrityBatch(scope,
      request([remove("operation-one", "missing-audit")]), executor))
      .rejects.toThrow("rejected operations");
    expect(executor.unlink).not.toHaveBeenCalled();
  });
  it("rejects stale expected event counts", async () => {
    const { executor } = fakeExecutor([linkEvent("audit-one")]);
    await expect(executeIntegrityBatch(scope, {
      ...request([add("operation-one", "case-two")]), expectedEventCount: 0,
    }, executor)).rejects.toThrow("rejected operations");
  });
  it("prevents non-administrators from executing a batch", async () => {
    const { executor } = fakeExecutor();
    await expect(executeIntegrityBatch({
      ...scope, role: "AUDITOR",
    }, request([add("operation-one", "case-one")]), executor))
      .rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(executor.readHistory).not.toHaveBeenCalled();
  });
  it("stops on the first mutation error by default", async () => {
    const { executor } = fakeExecutor();
    vi.mocked(executor.link).mockRejectedValueOnce(
      new WorkInputError("CONFLICT", "Concurrent conflict."));
    const result = await executeIntegrityBatch(scope, request([
      add("operation-one", "case-one"),
      add("operation-two", "case-two"),
    ]), executor);
    expect(result.failed).toBe(2);
    expect(result.stoppedEarly).toBe(true);
    expect(executor.link).toHaveBeenCalledTimes(1);
    expect(result.outcomes[1]?.errorCode).toBe("NOT_EXECUTED");
  });
  it("continues after errors when requested", async () => {
    const { executor } = fakeExecutor();
    vi.mocked(executor.link).mockRejectedValueOnce(
      new WorkInputError("CONFLICT", "Concurrent conflict."));
    const result = await executeIntegrityBatch(scope, request([
      add("operation-one", "case-one"),
      add("operation-two", "case-two"),
    ], "CONTINUE_ON_ERROR"), executor);
    expect(result.applied).toBe(1);
    expect(result.failed).toBe(1);
    expect(result.stoppedEarly).toBe(false);
  });
  it("rejects unknown execution modes", () => {
    expect(() => parseIntegrityBatchExecutionRequest(
      request([add("operation-one", "case-one")], "ATOMIC"),
    )).toThrow();
  });
  it("does not treat execution as a security verification", async () => {
    const { executor } = fakeExecutor();
    const result = await executeIntegrityBatch(scope,
      request([add("operation-one", "case-one")]), executor);
    expect(result.applied).toBe(1);
    expect("securityVerified" in result).toBe(false);
  });
});
