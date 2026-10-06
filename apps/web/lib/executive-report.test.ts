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

    vi.useRealTimers();
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
