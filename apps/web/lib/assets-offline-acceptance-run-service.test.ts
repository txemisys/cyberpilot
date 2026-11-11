import { describe, expect, it } from "vitest";
import {
  OPERATOR_STEP_CODES, parseOperatorRunCreate,
  parseOperatorRunChange, parseOperatorRunQuery,
  initialOperatorSteps, verifyOperatorSteps,
  applyOperatorStep, operatorRunReadiness,
  nextOperatorRunState,
} from "./assets-offline-acceptance-run-service";

const stamp = new Date("2026-11-11T12:00:00.000Z");
const digest = "a".repeat(64);
const reason = "Operator inspected source evidence and documented its limitations.";
const creator = (changes: Record<string, unknown> = {}) => ({
  importId: "import_12345",
  inspectionId: "inspect_12345",
  idempotencyKey: "run_12345",
  bindings: [],
  acceptancePolicy: {},
  privacyPolicy: {},
  reason,
  ...changes,
});
const changer = (changes: Record<string, unknown> = {}) => ({
  runId: "run_12345",
  expectedRevision: 1,
  expectedDossierDigest: digest,
  operation: "RECORD_EVIDENCE",
  stepCode: "CSV_IMPORT_REVIEW",
  evidenceId: "case-evidence-0001",
  evidenceDescription: "Operator reviewed a stored original CSV export",
  reason,
  limitations: [],
  acknowledgements: ["OFFLINE_ONLY"],
  bindings: [], acceptancePolicy: {}, privacyPolicy: {},
  ...changes,
});
describe("Fase 4 witnessed offline operator checklist contract", () => {
  it("defines nine unique operator steps with unselected evidence", () => {
    const steps = initialOperatorSteps();
    expect(OPERATOR_STEP_CODES).toHaveLength(9);
    expect(new Set(OPERATOR_STEP_CODES).size).toBe(9);
    expect(steps).toHaveLength(9);
    expect(steps.every(s => s.status === "TODO" &&
      s.evidenceId === null && s.recordedByUserId === null)).toBe(true);
    expect(verifyOperatorSteps(steps)).toMatchObject({
      valid: true, completed: 0, blocked: 0,
    });
  });
  it("parses an exact tenant-free bounded run creation", () => {
    const command = parseOperatorRunCreate(creator());
    expect(command).toMatchObject({
      importId: "import_12345", inspectionId: "inspect_12345",
      idempotencyKey: "run_12345",
    });
    expect(command).not.toHaveProperty("organizationId");
    expect(command).not.toHaveProperty("signedOff");
  });
  it.each([
    { importId: "" },
    { importId: "../foreign" },
    { inspectionId: "short" },
    { idempotencyKey: "x" },
    { bindings: "[]" },
    { reason: "short" },
    { organizationId: "foreign" },
    { actorUserId: "another-user" },
    { signedOff: true },
    { mergeAuthorized: true },
    { state: "EVIDENCE_CAPTURED" },
    { idempotencyKey: 1 },
  ])("rejects malformed or forged run input %j", extra => {
    expect(() => parseOperatorRunCreate(creator(extra))).toThrow();
  });
  it("parses an evidence CAS update without treating human input as proof", () => {
    const command = parseOperatorRunChange(changer());
    expect(command.operation).toBe("RECORD_EVIDENCE");
    expect(command.expectedRevision).toBe(1);
    expect(command.expectedDossierDigest).toBe(digest);
    expect(command.acknowledgements).toContain("OFFLINE_ONLY");
  });
  it.each([
    { runId: "../other" }, { runId: "" },
    { expectedRevision: 0 },
    { expectedRevision: -1 },
    { expectedRevision: "1" },
    { expectedRevision: 1.5 },
    { expectedDossierDigest: "a" },
    { expectedDossierDigest: digest.toUpperCase() },
    { operation: "ACCEPT_PHASE" },
    { operation: "AUTHORIZE_MERGE" },
    { operation: "LEGAL_SIGNOFF" },
    { stepCode: "FAKE_STEP" },
    { evidenceId: "short" },
    { evidenceDescription: "short" },
    { reason: "short" },
    { limitations: ["x"] },
    { acknowledgements: ["FAKE_ACK"] },
    { acknowledgements: ["OFFLINE_ONLY", "OFFLINE_ONLY"] },
    { organizationId: "foreign" },
    { actorUserId: "other" },
  ])("rejects invalid CAS input %j", extra => {
    expect(() => parseOperatorRunChange(changer(extra))).toThrow();
  });
  it("records evidence in exactly one selected step", () => {
    const command = parseOperatorRunChange(changer());
    const steps = applyOperatorStep(
      initialOperatorSteps(), command, "admin_12345", stamp);
    const selected = steps[0]!;
    expect(selected).toMatchObject({
      code: "CSV_IMPORT_REVIEW", status: "EVIDENCE_RECORDED",
      evidenceId: "case-evidence-0001",
      recordedByUserId: "admin_12345",
      attestationScope: "LOCAL_OPERATOR_DECLARATION_ONLY",
    });
    expect(selected.recordedAt).toBe(stamp.toISOString());
    expect(verifyOperatorSteps(steps)).toMatchObject({
      valid: true, completed: 1, blocked: 0,
    });
    expect(steps.slice(1).every(x => x.status === "TODO")).toBe(true);
  });
  it("blocks one step while retaining operator reason and timestamp", () => {
    const command = parseOperatorRunChange(changer({
      operation: "BLOCK_STEP", evidenceId: null,
      evidenceDescription: null,
      limitations: ["Provider coverage was incomplete"],
    }));
    const steps = applyOperatorStep(
      initialOperatorSteps(), command, "admin_12345", stamp);
    expect(steps[0]).toMatchObject({
      status: "BLOCKED", evidenceId: null,
      recordedByUserId: "admin_12345",
    });
    expect(verifyOperatorSteps(steps)).toMatchObject({
      valid: true, completed: 0, blocked: 1,
    });
  });
  it("can clear one step without clearing another", () => {
    let steps = applyOperatorStep(initialOperatorSteps(),
      parseOperatorRunChange(changer()), "admin_12345", stamp);
    steps = applyOperatorStep(steps, parseOperatorRunChange(changer({
      stepCode: "SCOPE_AND_PROVENANCE",
      evidenceId: "scope-evidence-0002",
    })), "admin_12345", stamp);
    steps = applyOperatorStep(steps, parseOperatorRunChange(changer({
      operation: "RESET_STEP", evidenceId: null,
      evidenceDescription: null,
    })), "admin_12345", stamp);
    expect(steps[0]!.status).toBe("TODO");
    expect(steps[1]!.status).toBe("EVIDENCE_RECORDED");
    expect(verifyOperatorSteps(steps).completed).toBe(1);
  });
  it("rejects evidence recording without a reference or description", () => {
    expect(() => applyOperatorStep(initialOperatorSteps(),
      parseOperatorRunChange(changer({ evidenceId: null })),
      "admin_12345", stamp)).toThrow();
    expect(() => applyOperatorStep(initialOperatorSteps(),
      parseOperatorRunChange(changer({ evidenceDescription: null })),
      "admin_12345", stamp)).toThrow();
  });
  it("never lets a started or blocked checklist submit early", () => {
    const steps = initialOperatorSteps();
    expect(operatorRunReadiness(steps, true, true))
      .toMatchObject({
        canSubmitForIndependentReview: false,
        completed: 0, blocked: 0,
        externalPrivacySignoffStillRequired: true,
        mergeAuthorizationGranted: false,
      });
    expect(nextOperatorRunState("IN_PROGRESS",
      "SUBMIT_FOR_INDEPENDENT_REVIEW", steps, false)).toBeNull();
    expect(nextOperatorRunState("DRAFT",
      "SUBMIT_FOR_INDEPENDENT_REVIEW", steps, true)).toBeNull();
  });
  it("permits evidence captured only after all nine witnessed steps", () => {
    let steps = initialOperatorSteps();
    for (const [index, code] of OPERATOR_STEP_CODES.entries()) {
      const command = parseOperatorRunChange(changer({
        stepCode: code,
        evidenceId: "evidence-record-" + index,
      }));
      steps = applyOperatorStep(
        steps, command, "admin_12345", stamp);
    }
    const ready = operatorRunReadiness(steps, true, true);
    expect(ready.canSubmitForIndependentReview).toBe(true);
    expect(ready.externalPrivacySignoffStillRequired).toBe(true);
    expect(ready.mergeAuthorizationGranted).toBe(false);
    expect(nextOperatorRunState("IN_PROGRESS",
      "SUBMIT_FOR_INDEPENDENT_REVIEW", steps, true))
      .toBe("EVIDENCE_CAPTURED");
  });
  it("does not confuse evidence readiness with an independent approval", () => {
    const empty = initialOperatorSteps();
    expect(operatorRunReadiness(empty, false, false)
      .externalPrivacySignoffStillRequired).toBe(true);
    expect(operatorRunReadiness(empty, true, true)
      .explicitHumanSignoffStillRequired).toBe(true);
    expect(operatorRunReadiness(empty, true, true)
      .liveProviderValidated).toBe(false);
  });
  it("rejects duplicate or removed steps and forged independent attestation", () => {
    const steps = initialOperatorSteps();
    steps[1]!.code = steps[0]!.code;
    expect(verifyOperatorSteps(steps).valid).toBe(false);
    const other = initialOperatorSteps();
    other[0]!.attestationScope = "INDEPENDENT_CERTIFIED" as
      typeof other[0]["attestationScope"];
    expect(verifyOperatorSteps(other).valid).toBe(false);
    expect(verifyOperatorSteps([]).valid).toBe(false);
  });
  it("checks legal state transitions without implicit acceptance", () => {
    const steps = initialOperatorSteps();
    expect(nextOperatorRunState("DRAFT", "START", steps, false))
      .toBe("IN_PROGRESS");
    expect(nextOperatorRunState("IN_PROGRESS", "START", steps, false))
      .toBeNull();
    expect(nextOperatorRunState("IN_PROGRESS",
      "BLOCK_STEP", [{ ...steps[0]!, status: "BLOCKED" }], false))
      .toBe("BLOCKED");
    expect(nextOperatorRunState("BLOCKED", "REOPEN", steps, false))
      .toBe("REOPENED");
    expect(nextOperatorRunState("EVIDENCE_CAPTURED", "REOPEN", steps, false))
      .toBe("REOPENED");
    expect(nextOperatorRunState("DRAFT", "REOPEN", steps, false))
      .toBeNull();
  });
  it("supports only bounded tenant-scoped lists", () => {
    expect(parseOperatorRunQuery()).toMatchObject({
      offset: 0, limit: 25, importId: null,
    });
    for (const option of [
      { offset: -1 }, { limit: 0 }, { limit: 101 },
      { state: "ACCEPTED_LIVE" },
      { organizationId: "foreign" },
      { importId: "../foreign" },
    ]) expect(() => parseOperatorRunQuery(option)).toThrow();
  });
});
