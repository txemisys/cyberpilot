import { describe, expect, it } from "vitest";

import { buildPilotReadiness } from "./pilot-readiness";

describe("buildPilotReadiness", () => {
  it("does not treat Lab Mode as a real customer pilot", () => {
    const result = buildPilotReadiness({
      scannerConfigured: false,
      remediationConfigured: false,
      integration: {
        mode: "LAB",
        status: "CONNECTED",
        lastSyncAt: new Date(),
      },
      readonlyProbeResult: null,
      hasScoreSnapshot: true,
    });

    expect(result.readyForReadOnlyAssessment).toBe(false);
    expect(result.steps.find((step) => step.id === "tenant")?.state).toBe(
      "BLOCKED",
    );
  });

  it("is ready only after a LIVE connection, healthy probe, sync and score snapshot", () => {
    const result = buildPilotReadiness({
      scannerConfigured: true,
      remediationConfigured: false,
      integration: {
        mode: "LIVE",
        status: "CONNECTED",
        lastSyncAt: new Date(),
      },
      readonlyProbeResult: "READY",
      hasScoreSnapshot: true,
    });

    expect(result.readyForReadOnlyAssessment).toBe(true);
    expect(result.needsAttention).toBe(false);
  });

  it("surfaces partial read-only evidence and configured write credentials", () => {
    const result = buildPilotReadiness({
      scannerConfigured: true,
      remediationConfigured: true,
      integration: {
        mode: "LIVE",
        status: "CONNECTED",
        lastSyncAt: null,
      },
      readonlyProbeResult: "PARTIAL",
      hasScoreSnapshot: false,
    });

    expect(result.readyForReadOnlyAssessment).toBe(false);
    expect(result.needsAttention).toBe(true);
    expect(result.steps.find((step) => step.id === "probe")?.state).toBe(
      "ATTENTION",
    );
    expect(result.steps.find((step) => step.id === "writes")?.state).toBe(
      "ATTENTION",
    );
  });
});
