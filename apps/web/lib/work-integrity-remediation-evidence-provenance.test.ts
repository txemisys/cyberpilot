import { describe, expect, it } from "vitest";
import {
  parseIntegrityExecutionEvidenceQuery,
  queryIntegrityExecutionEvidence,
} from "./work-integrity-remediation-evidence-provenance";
import {
  parseIntegrityExecutionControlPolicy,
  parseIntegrityExecutionControlQuery,
} from "./work-integrity-remediation-execution-controls";

describe("integrity execution provenance and governance validation", () => {
  it("rejects unknown evidence status filters", () => {
    expect(() => parseIntegrityExecutionEvidenceQuery({
      statuses: ["SECURITY_VERIFIED"],
    })).toThrow();
  });
  it("rejects reversed or invalid pagination bounds", () => {
    expect(() => parseIntegrityExecutionEvidenceQuery({
      limit: 0,
    })).toThrow();
  });
  it("rejects unsupported execution control policies", () => {
    expect(() => parseIntegrityExecutionControlPolicy({
      maximumAttemptsPerCandidate: 0,
    })).toThrow();
  });
  it("rejects unknown execution control issue codes", () => {
    expect(() => parseIntegrityExecutionControlQuery({
      issueCodes: ["NOT_A_CONTROL"],
    })).toThrow();
  });
  it("keeps pagination deterministic for empty provenance", () => {
    const page = queryIntegrityExecutionEvidence({
      schemaVersion: 1, captureId: "capture-one",
      limitation: "Not verified", references: [], candidates: [],
      findings: [], totals: {
        candidates: 0, executionEvents: 0, submittedReferences: 0,
        distinctReferences: 0, activeAssociations: 0,
        withdrawnAssociations: 0, unmatchedReferences: 0,
        crossCaseReferences: 0, ambiguousReferences: 0, findings: 0,
        errors: 0, warnings: 0, provenanceCompleteCandidates: 0,
        securityVerifiedCandidates: 0,
      },
    }, parseIntegrityExecutionEvidenceQuery({ offset: 2, limit: 10 }));
    expect(page.total).toBe(0);
    expect(page.hasMore).toBe(false);
  });
});
