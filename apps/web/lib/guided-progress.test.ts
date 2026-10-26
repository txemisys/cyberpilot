import { describe, expect, it } from "vitest";
import { parseGuidedStepIndex } from "./guided-progress";

describe("guided remediation progress input", () => {
  it("allows only valid indices within the approved playbook", () => {
    expect(parseGuidedStepIndex("0", 2)).toBe(0);
    expect(parseGuidedStepIndex("1", 2)).toBe(1);
    for (const value of ["-1", "02", "2", "1.0", "abc", "", "999999999999999999999999"]) {
      expect(parseGuidedStepIndex(value, 2)).toBeNull();
    }
    expect(parseGuidedStepIndex(null, 2)).toBeNull();
    expect(parseGuidedStepIndex("0", 0)).toBeNull();
  });
});
