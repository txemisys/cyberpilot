import { calculateCyberScore } from "@cyberpilot/risk-engine";

export type ExecutiveReportFinding = {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  firstSeenAt: Date;
  lastSeenAt: Date;
};

export type ExecutiveReportSnapshot = {
  score: number;
  riskPoints: number;
  coverage: "COMPLETE" | "PARTIAL";
  modelVersion: string;
  calculatedAt: Date;
};

export type ExecutiveReportDomain = {
  name: string;
  isDefault: boolean;
  isInitial: boolean;
  spfStatus: string;
  dmarcStatus: string;
  dmarcPolicy: string | null;
  dkimStatus: string;
};

export type ExecutiveReportRemediation = {
  title: string;
  mode: "GUIDED" | "AUTOMATED";
  status:
    | "PROPOSED"
    | "APPROVED"
    | "EXECUTING"
    | "SUCCEEDED"
    | "FAILED"
    | "CANCELLED"
    | "VERIFIED";
  completedAt: Date | null;
  findingTitle: string;
};

export type ExecutiveReportInput = {
  organizationName: string;
  integrationMode: "LIVE" | "LAB" | null;
  integrationDisplayName: string | null;
  lastSyncAt: Date | null;
  snapshot: ExecutiveReportSnapshot | null;
  previousSnapshot: ExecutiveReportSnapshot | null;
  baselineSnapshot: ExecutiveReportSnapshot | null;
  scoreHistory: ExecutiveReportSnapshot[];
  findings: ExecutiveReportFinding[];
  domains: ExecutiveReportDomain[];
  remediations: ExecutiveReportRemediation[];
};

export function buildExecutiveReport(input: ExecutiveReportInput) {
  const currentRisk = calculateCyberScore(
    input.findings.map((finding) => ({
      id: finding.id,
      ruleId: finding.ruleId,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
    })),
  );

  const severityCounts = input.findings.reduce(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    {
      INFO: 0,
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0,
      CRITICAL: 0,
    },
  );

  const verifiedRemediations = input.remediations.filter(
    (remediation) => remediation.status === "VERIFIED",
  );

  const headlineScore = input.snapshot?.score ?? currentRisk.score;
  const postureStatus =
    severityCounts.CRITICAL > 0
      ? "CRITICAL"
      : severityCounts.HIGH > 0 || headlineScore < 80
        ? "NEEDS_ATTENTION"
        : "HEALTHY";

  const comparableHistory = input.scoreHistory
    .filter(
      (snapshot) =>
        !input.snapshot || snapshot.modelVersion === input.snapshot.modelVersion,
    )
    .slice()
    .sort(
      (left, right) =>
        left.calculatedAt.getTime() - right.calculatedAt.getTime(),
    );

  const scoreDelta =
    input.snapshot &&
    input.previousSnapshot &&
    input.snapshot.modelVersion === input.previousSnapshot.modelVersion
      ? input.snapshot.score - input.previousSnapshot.score
      : null;

  const baselineDelta =
    input.snapshot &&
    input.baselineSnapshot &&
    input.snapshot.modelVersion === input.baselineSnapshot.modelVersion
      ? input.snapshot.score - input.baselineSnapshot.score
      : null;

  return {
    ...input,
    currentRisk,
    severityCounts,
    verifiedRemediations,
    postureStatus,
    comparableHistory,
    scoreDelta,
    baselineDelta,
    generatedAt: new Date(),
    isLab: input.integrationMode === "LAB",
  };
}
