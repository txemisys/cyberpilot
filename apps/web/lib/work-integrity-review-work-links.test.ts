import { describe, expect, it } from "vitest";
import {
  nextReviewWorkLinkState,
  parseReviewWorkCommand,
  parseReviewWorkQuery,
} from "./work-integrity-review-work-links";

const valid = {
  taskId: "review-task-12345",
  workItemId: "work-item-12345",
  action: "LINK",
  expectedRevision: 0,
  rationale: "This remediation work item is associated with the case.",
};
describe("review-work association validation", () => {
  it("parses a first association", () => {
    expect(parseReviewWorkCommand(valid)).toEqual(valid);
  });
  it.each(["LINK", "UNLINK", "RELINK"])(
    "accepts %s as a supported lifecycle action", action => {
      expect(parseReviewWorkCommand({ ...valid, action }).action).toBe(action);
    },
  );
  it.each([
    { action: "VERIFY" },
    { action: "DELETE" },
    { action: null },
    { taskId: "../other" },
    { workItemId: "bad" },
    { expectedRevision: -1 },
    { expectedRevision: 1.5 },
    { expectedRevision: "1" },
    { expectedRevision: 2147483647 },
    { rationale: "short" },
    { rationale: "x".repeat(4001) },
    { rationale: "contains\ncontrol characters" },
    { unexpected: true },
  ])("rejects invalid commands %j", patch => {
    expect(() => parseReviewWorkCommand({
      ...valid, ...patch,
    })).toThrow();
  });
  it("rejects non-object commands", () => {
    for (const input of [null, [], "bad", 7, {}])
      expect(() => parseReviewWorkCommand(input)).toThrow();
  });
  it("requires at least one filter for list operations", () => {
    expect(() => parseReviewWorkQuery({})).toThrow();
  });
  it("parses bounded list query", () => {
    expect(parseReviewWorkQuery({
      taskId: valid.taskId,
    })).toEqual({
      taskId: valid.taskId, includeInactive: false,
      offset: 0, limit: 50,
    });
    expect(parseReviewWorkQuery({
      workItemId: valid.workItemId, includeInactive: true,
      offset: 10, limit: 200,
    })).toMatchObject({
      includeInactive: true, offset: 10, limit: 200,
    });
  });
  it.each([
    { offset: -1 },
    { offset: "1" },
    { offset: 1000001 },
    { limit: 0 },
    { limit: 201 },
    { limit: 2.5 },
    { includeInactive: "true" },
    { extra: "x" },
  ])("rejects invalid list query %j", patch => {
    expect(() => parseReviewWorkQuery({
      taskId: valid.taskId, ...patch,
    })).toThrow();
  });
});
describe("review-work link lifecycle", () => {
  const active = { revision: 1, unlinkedAt: null };
  const inactive = {
    revision: 2, unlinkedAt: new Date("2026-10-01T00:00:00Z"),
  };
  it("creates the initial active association", () => {
    expect(nextReviewWorkLinkState("LINK", null, 0)).toEqual({
      revision: 1, active: true,
    });
  });
  it("rejects duplicate initial association", () => {
    expect(() => nextReviewWorkLinkState("LINK", active, 1)).toThrow();
  });
  it("rejects stale initial revision", () => {
    expect(() => nextReviewWorkLinkState("LINK", null, 1)).toThrow();
  });
  it("unlinks an active association", () => {
    expect(nextReviewWorkLinkState("UNLINK", active, 1)).toEqual({
      revision: 2, active: false,
    });
  });
  it("rejects unlink of absent association", () => {
    expect(() => nextReviewWorkLinkState("UNLINK", null, 0)).toThrow();
  });
  it("rejects duplicate unlink", () => {
    expect(() => nextReviewWorkLinkState("UNLINK", inactive, 2)).toThrow();
  });
  it("relinks an inactive association", () => {
    expect(nextReviewWorkLinkState("RELINK", inactive, 2)).toEqual({
      revision: 3, active: true,
    });
  });
  it("rejects relinking an already active association", () => {
    expect(() => nextReviewWorkLinkState("RELINK", active, 1)).toThrow();
  });
  it("rejects stale revisions on all lifecycle actions", () => {
    for (const action of ["UNLINK", "RELINK", "LINK"] as const)
      expect(() => nextReviewWorkLinkState(action, inactive, 1)).toThrow();
  });
});
