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
        score: 11,
        riskPoints: 89.2,
        coverage: "COMPLETE",
        modelVersion: "v0",
        calculatedAt: new Date("2026-10-06T11:00:00.000Z"),
      },
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
    expect(report.scoreDelta).toBe(59);
    expect(report.currentRisk.score).toBe(70);
    expect(report.verifiedRemediations).toHaveLength(1);
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
