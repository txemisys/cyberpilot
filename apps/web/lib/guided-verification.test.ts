import { describe, expect, it } from "vitest";
import { getGuidedVerificationReadiness } from "./guided-verification";

describe("guided verification readiness", () => {
  it("does not treat an empty playbook as complete", () => {
    expect(getGuidedVerificationReadiness(0, new Set())).toBe("NO_STEPS");
  });

  it("requires every individual step to be acknowledged", () => {
    expect(getGuidedVerificationReadiness(2, new Set([0]))).toBe("IN_PROGRESS");
    expect(getGuidedVerificationReadiness(2, new Set([1]))).toBe("IN_PROGRESS");
    expect(getGuidedVerificationReadiness(2, new Set([0, 1]))).toBe("READY");
  });

  it("ignores stray or out-of-range progress", () => {
    expect(getGuidedVerificationReadiness(2, new Set([2, 3]))).toBe("IN_PROGRESS");
  });
});
