export type PilotReadinessState =
  | "COMPLETE"
  | "READY"
  | "PENDING"
  | "ATTENTION"
  | "BLOCKED";

export type PilotReadinessInput = {
  scannerConfigured: boolean;
  remediationConfigured: boolean;
  integration: {
    mode: "LIVE" | "LAB";
    status: "PENDING" | "CONNECTED" | "ERROR" | "DISCONNECTED";
    lastSyncAt: Date | null;
  } | null;
  readonlyProbeResult: "READY" | "PARTIAL" | "ERROR" | null;
  hasScoreSnapshot: boolean;
};

export type PilotReadinessStep = {
  id: string;
  title: string;
  state: PilotReadinessState;
  detail: string;
};

export function buildPilotReadiness(input: PilotReadinessInput) {
  const liveConnected =
    input.integration?.mode === "LIVE" &&
    input.integration.status === "CONNECTED";

  const steps: PilotReadinessStep[] = [
    {
      id: "workspace",
      title: "CyberPilot workspace",
      state: "COMPLETE",
      detail: "Organization and access boundary are established.",
    },
    {
      id: "scanner",
      title: "Read-only scanner configuration",
      state: input.scannerConfigured ? "READY" : "BLOCKED",
      detail: input.scannerConfigured
        ? "Dedicated Microsoft 365 scanner credentials and callback are configured."
        : "Configure the dedicated scanner app before starting tenant consent.",
    },
    {
      id: "tenant",
      title: "Microsoft 365 tenant connection",
      state: liveConnected
        ? "COMPLETE"
        : input.integration?.mode === "LAB"
          ? "BLOCKED"
          : "PENDING",
      detail: liveConnected
        ? "A real Microsoft 365 tenant is connected in LIVE mode."
        : input.integration?.mode === "LAB"
          ? "Lab evidence is synthetic and does not count as a customer tenant connection."
          : "A tenant administrator must complete read-only admin consent.",
    },
    {
      id: "probe",
      title: "Read-only access probe",
      state:
        input.readonlyProbeResult === "READY"
          ? "COMPLETE"
          : input.readonlyProbeResult === "PARTIAL"
            ? "ATTENTION"
            : input.readonlyProbeResult === "ERROR"
              ? "BLOCKED"
              : "PENDING",
      detail:
        input.readonlyProbeResult === "READY"
          ? "Organization, users, roles and authentication-registration evidence are readable."
          : input.readonlyProbeResult === "PARTIAL"
            ? "At least one read-only evidence scope still needs Microsoft admin consent."
            : input.readonlyProbeResult === "ERROR"
              ? "The latest read-only probe failed and must be resolved before the pilot."
              : "Run the read-only Microsoft access test after connecting the tenant.",
    },
    {
      id: "sync",
      title: "First evidence synchronization",
      state: liveConnected && input.integration?.lastSyncAt ? "COMPLETE" : "PENDING",
      detail:
        liveConnected && input.integration?.lastSyncAt
          ? "The first LIVE evidence inventory has completed."
          : "Run the first LIVE sync only after the read-only probe is satisfactory.",
    },
    {
      id: "report",
      title: "Executive assessment evidence",
      state: liveConnected && input.hasScoreSnapshot ? "COMPLETE" : "PENDING",
      detail:
        liveConnected && input.hasScoreSnapshot
          ? "An immutable CyberScore snapshot is available for the executive report."
          : "The first LIVE score snapshot and executive report are still pending.",
    },
    {
      id: "writes",
      title: "Microsoft write capability",
      state: input.remediationConfigured ? "ATTENTION" : "COMPLETE",
      detail: input.remediationConfigured
        ? "Remediation credentials are configured. Keep write consent disabled during the first read-only pilot."
        : "Remediation credentials are not configured, which is the preferred state for the first pilot.",
    },
  ];

  const blocking = steps.some((step) => step.state === "BLOCKED");
  const attention = steps.some((step) => step.state === "ATTENTION");
  const requiredComplete = ["scanner", "tenant", "probe", "sync", "report"].every(
    (id) => {
      const step = steps.find((candidate) => candidate.id === id);
      return step?.state === "COMPLETE" || step?.state === "READY";
    },
  );

  return {
    steps,
    readyForReadOnlyAssessment: requiredComplete && !blocking,
    needsAttention: attention,
  };
}
