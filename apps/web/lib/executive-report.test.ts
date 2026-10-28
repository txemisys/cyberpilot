import { describe, expect, it, vi } from "vitest";

import { buildExecutiveReport } from "./executive-report";

describe("buildExecutiveReport", () => {
  it("keeps the immutable snapshot score while deriving priorities from current findings", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-06T12:00:00.000Z"));

    const report = buildExecutiveReport({
      organizationName: "CasaDeCosi",
      integrationMode: "LAB",
      integrationDisplayName: "CyberPilot Microsoft 365 Lab",
      lastSyncAt: new Date("2026-10-06T11:50:00.000Z"),
      snapshot: {
        score: 70,
        riskPoints: 29.7,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date("2026-10-06T11:50:01.000Z"),
      },
      previousSnapshot: {
        score: 70,
        riskPoints: 29.7,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date("2026-10-06T11:40:00.000Z"),
      },
      baselineSnapshot: {
        score: 11,
        riskPoints: 89.2,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date("2026-10-06T11:00:00.000Z"),
      },
      scoreHistory: [
        {
          score: 70,
          riskPoints: 29.7,
          coverage: "COMPLETE",
          modelVersion: "v0",
          calculatedAt: new Date("2026-10-06T11:50:01.000Z"),
        },
        {
          score: 11,
          riskPoints: 89.2,
          coverage: "COMPLETE",
          modelVersion: "v0",
          calculatedAt: new Date("2026-10-06T11:00:00.000Z"),
        },
      ],
      findings: [
        {
          id: "mfa",
          ruleId: "M365_ADMIN_MFA_NOT_CAPABLE",
          title: "Administrator is not MFA-capable",
          description: "Test finding",
          severity: "HIGH",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
        {
          id: "dmarc",
          ruleId: "DOMAIN_DMARC_MONITORING_ONLY",
          title: "DMARC is monitoring only",
          description: "Test finding",
          severity: "MEDIUM",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
        {
          id: "dkim",
          ruleId: "DOMAIN_M365_DKIM_SELECTORS_PARTIAL",
          title: "Microsoft 365 DKIM selectors are incomplete",
          description: "Test finding",
          severity: "LOW",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
      ],
      domains: [],
      remediations: [
        {
          title: "Remove guest Global Administrator assignment",
          mode: "AUTOMATED",
          status: "VERIFIED",
          completedAt: new Date(),
          findingTitle: "Guest user is a Global Administrator",
        },
      ],
    });

    expect(report.snapshot?.score).toBe(70);
    expect(report.scoreDelta).toBe(0);
    expect(report.baselineDelta).toBe(59);
    expect(report.currentRisk.score).toBe(70);
    expect(report.verifiedRemediations).toHaveLength(1);
    expect(report.postureStatus).toBe("NEEDS_ATTENTION");
    expect(report.comparableHistory.map((snapshot) => snapshot.score)).toEqual([
      11,
      70,
    ]);
    expect(report.severityCounts).toMatchObject({
      HIGH: 1,
      MEDIUM: 1,
      LOW: 1,
      CRITICAL: 0,
    });
    expect(report.isLab).toBe(true);
    expect(report.nextActions.length).toBeGreaterThan(0);
    expect(report.nextActions.length).toBeLessThanOrEqual(3);
    expect(report.nextActions[0]).toMatchObject({ title: expect.any(String), remediation: expect.any(String) });

    vi.useRealTimers();
  });
});


describe("executive score model comparability", () => {
  const snapshot = {
    score: 85,
    riskPoints: 15,
    coverage: "COMPLETE" as const,
    modelVersion: "v2",
    calculatedAt: new Date("2026-10-28T10:00:00.000Z"),
  };

  it("never presents a score delta against a different model version", () => {
    const earlier = { ...snapshot, score: 55, modelVersion: "v1", calculatedAt: new Date("2026-10-27T10:00:00.000Z") };
    const report = buildExecutiveReport({
      organizationName: "Model upgrade lab",
      integrationMode: "LAB",
      integrationDisplayName: "Synthetic",
      lastSyncAt: snapshot.calculatedAt,
      snapshot,
      previousSnapshot: earlier,
      baselineSnapshot: earlier,
      scoreHistory: [earlier, snapshot],
      findings: [],
      domains: [],
      remediations: [],
    });
    expect(report.scoreDelta).toBeNull();
    expect(report.baselineDelta).toBeNull();
    expect(report.comparableHistory).toEqual([snapshot]);
    expect(report.snapshot?.score).toBe(85);
  });

  it("calculates deltas and chronological history within the same model version", () => {
    const earlier = { ...snapshot, score: 75, calculatedAt: new Date("2026-10-27T10:00:00.000Z") };
    const report = buildExecutiveReport({
      organizationName: "Stable model lab",
      integrationMode: "LAB",
      integrationDisplayName: "Synthetic",
      lastSyncAt: snapshot.calculatedAt,
      snapshot,
      previousSnapshot: earlier,
      baselineSnapshot: earlier,
      scoreHistory: [snapshot, earlier],
      findings: [],
      domains: [],
      remediations: [],
    });
    expect(report.scoreDelta).toBe(10);
    expect(report.baselineDelta).toBe(10);
    expect(report.comparableHistory).toEqual([earlier, snapshot]);
  });
});

describe("executive posture classification", () => {
  const base = {
    organizationName: "Test",
    integrationMode: "LIVE" as const,
    integrationDisplayName: "Tenant",
    lastSyncAt: new Date(),
    previousSnapshot: null,
    baselineSnapshot: null,
    scoreHistory: [],
    domains: [],
    remediations: [],
  };

  it("does not label an organization healthy before any score snapshot exists", () => {
    const report = buildExecutiveReport({ ...base, snapshot: null, findings: [] });
    expect(report.postureStatus).toBe("UNASSESSED");
    expect(report.snapshot).toBeNull();
  });

  it("requires a completed snapshot even when an open critical finding is known", () => {
    const report = buildExecutiveReport({
      ...base, snapshot: null,
      findings: [{
        id: "critical", ruleId: "M365_GUEST_GLOBAL_ADMIN", title: "Critical",
        description: "Critical", severity: "CRITICAL",
        firstSeenAt: new Date(), lastSeenAt: new Date(),
      }],
    });
    expect(report.postureStatus).toBe("UNASSESSED");
    expect(report.severityCounts.CRITICAL).toBe(1);
  });

  it("does not call a snapshot healthy when no inventory sync is recorded", () => {
    const report = buildExecutiveReport({
      ...base,
      lastSyncAt: null,
      snapshot: {
        score: 100,
        riskPoints: 0,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date(),
      },
      findings: [],
    });
    expect(report.postureStatus).toBe("UNASSESSED");
    expect(report.snapshot?.score).toBe(100);
  });

  it("preserves a critical classification when a sync has completed", () => {
    const report = buildExecutiveReport({
      ...base,
      snapshot: {
        score: 90, riskPoints: 10, coverage: "COMPLETE",
        modelVersion: "v0", calculatedAt: new Date(),
      },
      findings: [{
        id: "critical", ruleId: "M365_GUEST_GLOBAL_ADMIN",
        title: "Critical", description: "Critical", severity: "CRITICAL",
        firstSeenAt: new Date(), lastSeenAt: new Date(),
      }],
    });
    expect(report.postureStatus).toBe("CRITICAL");
  });

  it("is critical when a critical finding is open", () => {
    const report = buildExecutiveReport({
      ...base,
      snapshot: {
        score: 90,
        riskPoints: 10,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date(),
      },
      findings: [
        {
          id: "critical",
          ruleId: "M365_GUEST_GLOBAL_ADMIN",
          title: "Critical",
          description: "Critical",
          severity: "CRITICAL",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
      ],
    });

    expect(report.postureStatus).toBe("CRITICAL");
  });

  it("does not call a partial-coverage snapshot healthy even with a high score", () => {
    const report = buildExecutiveReport({
      ...base,
      snapshot: {
        score: 95,
        riskPoints: 5,
        coverage: "PARTIAL",
        modelVersion: "v0",
        calculatedAt: new Date(),
      },
      findings: [],
    });
    expect(report.postureStatus).toBe("NEEDS_ATTENTION");
    expect(report.snapshot?.coverage).toBe("PARTIAL");
  });

  it("keeps critical posture when coverage is partial and a critical finding exists", () => {
    const report = buildExecutiveReport({
      ...base,
      snapshot: {
        score: 95, riskPoints: 5, coverage: "PARTIAL",
        modelVersion: "v0", calculatedAt: new Date(),
      },
      findings: [{
        id: "critical", ruleId: "M365_GUEST_GLOBAL_ADMIN", title: "Critical",
        description: "Critical", severity: "CRITICAL",
        firstSeenAt: new Date(), lastSeenAt: new Date(),
      }],
    });
    expect(report.postureStatus).toBe("CRITICAL");
  });

  it("is healthy only without high/critical findings and score at least 80", () => {
    const report = buildExecutiveReport({
      ...base,
      snapshot: {
        score: 92,
        riskPoints: 8,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date(),
      },
      findings: [
        {
          id: "low",
          ruleId: "DOMAIN_M365_DKIM_SELECTORS_PARTIAL",
          title: "Low",
          description: "Low",
          severity: "LOW",
          firstSeenAt: new Date(),
          lastSeenAt: new Date(),
        },
      ],
    });

    expect(report.postureStatus).toBe("HEALTHY");
  });
});
