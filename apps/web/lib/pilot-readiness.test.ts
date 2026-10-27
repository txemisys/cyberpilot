import { describe, expect, it } from "vitest";

import { buildPilotReadiness } from "./pilot-readiness";

describe("buildPilotReadiness", () => {
  it("does not treat Lab Mode as a real customer pilot", () => {
    const result = buildPilotReadiness({
      scannerConfigured: false,
      configurationSafe: false,
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
      configurationSafe: true,
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
      configurationSafe: false,
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
      "BLOCKED",
    );
    expect(result.steps.find((step) => step.id === "preflight")?.state).toBe(
      "BLOCKED",
    );
  });
  it.each([
    { label: "no scanner app", scannerConfigured: false },
    { label: "unsafe first-LIVE preflight", configurationSafe: false },
    { label: "write credentials present", remediationConfigured: true },
    { label: "consent probe incomplete", readonlyProbeResult: "PARTIAL" as const },
    { label: "consent probe failed", readonlyProbeResult: "ERROR" as const },
    { label: "consent probe never run", readonlyProbeResult: null },
    { label: "no completed inventory", hasScoreSnapshot: false },
    { label: "no prior synchronization", integration: { mode: "LIVE" as const, status: "CONNECTED" as const, lastSyncAt: null } },
    { label: "integration disconnected", integration: { mode: "LIVE" as const, status: "DISCONNECTED" as const, lastSyncAt: new Date() } },
    { label: "integration in error", integration: { mode: "LIVE" as const, status: "ERROR" as const, lastSyncAt: new Date() } },
    { label: "synthetic LAB evidence", integration: { mode: "LAB" as const, status: "CONNECTED" as const, lastSyncAt: new Date() } },
  ])("fails closed when $label", (override) => {
    const readiness = buildPilotReadiness({
      scannerConfigured: true,
      configurationSafe: true,
      remediationConfigured: false,
      integration: {
        mode: "LIVE",
        status: "CONNECTED",
        lastSyncAt: new Date(),
      },
      readonlyProbeResult: "READY",
      hasScoreSnapshot: true,
      ...override,
    });
    expect(readiness.readyForReadOnlyAssessment).toBe(false);
  });

  it("does not confuse partial evidence with successful consent even after a prior sync", () => {
    const readiness = buildPilotReadiness({
      scannerConfigured: true,
      configurationSafe: true,
      remediationConfigured: false,
      integration: { mode: "LIVE", status: "CONNECTED", lastSyncAt: new Date() },
      readonlyProbeResult: "PARTIAL",
      hasScoreSnapshot: true,
    });
    expect(readiness.readyForReadOnlyAssessment).toBe(false);
    expect(readiness.needsAttention).toBe(true);
    expect(readiness.steps.find((step) => step.id === "probe")?.state).toBe("ATTENTION");
  });

});
