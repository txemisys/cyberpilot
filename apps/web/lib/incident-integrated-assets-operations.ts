import { createHash } from "node:crypto";
import type { AffectedDevice, AssetImpactAssessment,
  AssetImpactOutcome } from "./incident-integrated-assets-domain";
export type AssetResponsePriority = "P0" | "P1" | "P2" | "P3";
export type AssetIncidentAction = {
  id: string; incidentId: string; organizationId: string;
  deviceId: string; importId: string; kind: "IDENTITY_CONFIRMATION" |
    "VERSION_REVIEW" | "ADVISORY_REVIEW" | "FRESHNESS_RECHECK" |
    "CONFLICT_RESOLUTION" | "ISOLATION_HANDOFF" |
    "OWNERSHIP_REVIEW";
  urgency: AssetResponsePriority; rationale: string;
  expectedProof: string[]; fallback: string;
  operatorRole: string; approvalRequired: boolean;
  queuedAt: string; targetBy: string; providerWrites: 0;
  executableWithoutHumanApproval: false;
};
export type AssetResponsePlan = {
  schema: "cyberpilot.incident.asset-response.plan.v1";
  organizationId: string; incidentId: string; at: string;
  inputDigest: string; actions: AssetIncidentAction[];
  affectedDeviceCount: number;
  priorityCounts: Record<AssetResponsePriority, number>;
  unknownOwners: number; advisoryCandidates: number;
  staleDeviceCount: number; missingDeviceCount: number;
  unresolvedConflictCount: number; totalActions: number;
  truncated: boolean; operatorReviewRequired: true;
  providerOperationsPerformed: 0; actualIsolationEstablished: false;
};
const priorityWeight: Record<AssetResponsePriority, number> =
  { P0: 4, P1: 3, P2: 2, P3: 1 };
function schedule(at: string, urgency: AssetResponsePriority) {
  const minutes: Record<AssetResponsePriority, number> =
    { P0: 15, P1: 60, P2: 240, P3: 1440 };
  return new Date(Date.parse(at) + minutes[urgency] * 60000).toISOString();
}
const severity = (device: AffectedDevice, kind: AssetIncidentAction["kind"]):
  AssetResponsePriority =>
  kind === "ISOLATION_HANDOFF" ? "P0" :
    kind === "CONFLICT_RESOLUTION" ? "P1" :
    device.advisoryStatus !== "NONE" || kind === "ADVISORY_REVIEW" ? "P1" :
    device.outcome === "STALE_ASSET" || device.outcome === "UNKNOWN_VERSION" ?
      "P2" : "P3";
function makeAction(device: AffectedDevice, kind: AssetIncidentAction["kind"],
  at: string): AssetIncidentAction {
  const urgency = severity(device, kind);
  const spec: Record<AssetIncidentAction["kind"], {
    rationale: string; expectedProof: string[]; fallback: string;
    operatorRole: string; approvalRequired: boolean;
  }> = {
    IDENTITY_CONFIRMATION: {
      rationale: "An inventory external ID is not proof of a physical device or user identity",
      expectedProof: ["Trusted device identifier", "Independent inventory owner confirmation"],
      fallback: "Keep target UNKNOWN and do not issue isolation or wipe",
      operatorRole: "IT asset owner", approvalRequired: false,
    },
    VERSION_REVIEW: {
      rationale: "Incomplete OS/software version prevents reliable vulnerability attribution",
      expectedProof: ["Current device inventory", "Version from authorized management plane"],
      fallback: "Treat vulnerability applicability as unknown",
      operatorRole: "Asset administrator", approvalRequired: false,
    },
    ADVISORY_REVIEW: {
      rationale: "An advisory candidate is not a confirmed exploited vulnerability",
      expectedProof: ["Matched product identifier", "OSV query provenance", "Patch or mitigation decision"],
      fallback: "Keep advisory as possible until reviewed",
      operatorRole: "Vulnerability reviewer", approvalRequired: false,
    },
    FRESHNESS_RECHECK: {
      rationale: "Historic device observation cannot describe current isolation or compromise",
      expectedProof: ["Current inventory timestamp", "Source data retention and completeness"],
      fallback: "Keep stale/unknown state rather than asserting safety",
      operatorRole: "Asset administrator", approvalRequired: false,
    },
    CONFLICT_RESOLUTION: {
      rationale: "Multiple inventory imports report the same external device identifier",
      expectedProof: ["Canonical inventory source and revision",
        "Explicit de-duplication decision with provenance"],
      fallback: "Do not arbitrarily choose a winning import",
      operatorRole: "Security reviewer", approvalRequired: false,
    },
    ISOLATION_HANDOFF: {
      rationale: "Severe device-related incident may need tenant-admin-approved containment",
      expectedProof: ["Verified target identity", "Approved isolation scope",
        "Independent provider isolation readback"],
      fallback: "Contact authorized administrator; no device commands are executed",
      operatorRole: "Incident commander", approvalRequired: true,
    },
    OWNERSHIP_REVIEW: {
      rationale: "Asset inventory owner attribution remains unverified",
      expectedProof: ["Current assignment from trusted management plane",
        "Authorized owner confirmation"],
      fallback: "Leave responsible person unconfirmed",
      operatorRole: "IT asset owner", approvalRequired: false,
    },
  };
  const item = spec[kind];
  return { id: device.id + ":" + kind, incidentId: device.incidentId,
    organizationId: device.organizationId, deviceId: device.id,
    importId: device.inventoryImportId, kind, urgency,
    rationale: item.rationale, expectedProof: item.expectedProof,
    fallback: item.fallback, operatorRole: item.operatorRole,
    approvalRequired: item.approvalRequired, queuedAt: at,
    targetBy: schedule(at, urgency),
    providerWrites: 0, executableWithoutHumanApproval: false };
}
export function planIncidentAssetActions(
  impact: AssetImpactAssessment,
): AssetResponsePlan {
  if (impact.affectedDevices.length > 600 ||
      impact.affectedDevices.some(x => x.organizationId !== impact.organizationId ||
      x.incidentId !== impact.incidentId))
    throw Error("ASSET_RESPONSE_SCOPE_INVALID");
  const actions: AssetIncidentAction[] = [];
  for (const device of impact.affectedDevices) {
    actions.push(makeAction(device, "IDENTITY_CONFIRMATION", impact.at));
    if (device.outcome === "STALE_ASSET")
      actions.push(makeAction(device, "FRESHNESS_RECHECK", impact.at));
    if (device.outcome === "UNKNOWN_VERSION" || device.osVersion === null)
      actions.push(makeAction(device, "VERSION_REVIEW", impact.at));
    if (device.advisoryStatus !== "NONE")
      actions.push(makeAction(device, "ADVISORY_REVIEW", impact.at));
    if (device.outcome === "CONFLICTED_IMPORT")
      actions.push(makeAction(device, "CONFLICT_RESOLUTION", impact.at));
    if (impact.incidentType === "RANSOMWARE" ||
        impact.incidentType === "LOST_DEVICE")
      actions.push(makeAction(device, "ISOLATION_HANDOFF", impact.at));
    actions.push(makeAction(device, "OWNERSHIP_REVIEW", impact.at));
  }
  actions.sort((a, b) => priorityWeight[b.urgency] - priorityWeight[a.urgency] ||
    a.targetBy.localeCompare(b.targetBy) || a.id.localeCompare(b.id));
  const priorityCounts = Object.fromEntries(
    (["P0", "P1", "P2", "P3"] as const).map(priority =>
      [priority, actions.filter(x => x.urgency === priority).length]))
    as Record<AssetResponsePriority, number>;
  return {
    schema: "cyberpilot.incident.asset-response.plan.v1",
    organizationId: impact.organizationId, incidentId: impact.incidentId,
    at: impact.at, inputDigest: impact.sourceDigest,
    actions: actions.slice(0, 3000), affectedDeviceCount: impact.affectedDevices.length,
    priorityCounts, unknownOwners: impact.affectedDevices.filter(x =>
      x.needsHumanAttribution).length,
    advisoryCandidates: impact.affectedDevices.filter(x =>
      x.advisoryStatus !== "NONE").length,
    staleDeviceCount: impact.staleDeviceIds.length,
    missingDeviceCount: impact.missingDeviceIds.length,
    unresolvedConflictCount: impact.conflictingExternalIds.length,
    totalActions: actions.length, truncated: impact.truncated ||
      actions.length > 3000,
    operatorReviewRequired: true,
    providerOperationsPerformed: 0, actualIsolationEstablished: false,
  };
}
export type AssetImpactCrossCheck = {
  schema: "cyberpilot.incident.asset-crosscheck.v1";
  organizationId: string; incidentId: string;
  conflictingIds: string[]; duplicateDeviceRows: string[];
  inconsistentAdvisories: string[]; unmatchedAdvisoryImports: string[];
  unsupportedObservations: string[];
  unresolvedCount: number; findings: string[];
  inputDigest: string; verifiedIsolationCount: 0;
};
export function crossCheckIncidentAssetSources(
  impact: AssetImpactAssessment,
): AssetImpactCrossCheck {
  const seen = new Set<string>(), duplicates: string[] = [];
  for (const device of impact.affectedDevices) {
    if (seen.has(device.id)) duplicates.push(device.id);
    seen.add(device.id);
  }
  const unmatchedAdvisoryImports = impact.advisoryObservations
    .filter(x => !impact.affectedDevices.some(d =>
      d.inventoryImportId === x.inventoryImportId))
    .map(x => x.inventoryImportId);
  const inconsistentAdvisories = impact.affectedDevices.filter(x =>
    x.advisoryStatus === "NONE" && x.advisoryIds.length > 0 ||
    x.advisoryStatus !== "NONE" && x.advisoryIds.length === 0)
    .map(x => x.id);
  const unsupportedObservations = impact.affectedDevices.filter(x =>
    x.observedAt > impact.at || x.confidence === "UNKNOWN")
    .map(x => x.id);
  const findings = [
    ...(impact.conflictingExternalIds.length ? ["INVENTORY_IDENTITY_CONFLICT"] : []),
    ...(duplicates.length ? ["DUPLICATE_DEVICE_ROWS"] : []),
    ...(unmatchedAdvisoryImports.length ? ["INSPECTION_WITHOUT_SELECTED_DEVICE"] : []),
    ...(inconsistentAdvisories.length ? ["ADVISORY_SOURCE_DISAGREEMENT"] : []),
    ...(unsupportedObservations.length ? ["FUTURE_OR_UNKNOWN_OBSERVATION"] : []),
    ...(impact.truncated ? ["CANNOT_PROVE_COMPLETE_ASSET_POPULATION"] : []),
  ];
  return { schema: "cyberpilot.incident.asset-crosscheck.v1",
    organizationId: impact.organizationId, incidentId: impact.incidentId,
    conflictingIds: impact.conflictingExternalIds, duplicateDeviceRows: duplicates,
    inconsistentAdvisories, unmatchedAdvisoryImports, unsupportedObservations,
    unresolvedCount: impact.conflictingExternalIds.length + duplicates.length +
      inconsistentAdvisories.length + unmatchedAdvisoryImports.length +
      unsupportedObservations.length, findings,
    inputDigest: impact.sourceDigest, verifiedIsolationCount: 0 };
}
function csv(value: unknown) {
  const raw = String(value ?? "");
  return '"' + (/^[=+\-@\t\r]/.test(raw) ? "'" + raw : raw)
    .replaceAll('"', '""').replaceAll("\n", " ").replaceAll("\r", " ") + '"';
}
export function exportIncidentAssetImpact(
  impact: AssetImpactAssessment, format: "JSON" | "CSV" | "MARKDOWN",
) {
  const plan = planIncidentAssetActions(impact);
  const crosscheck = crossCheckIncidentAssetSources(impact);
  const manifest = { impact, plan, crosscheck,
    providerIsolationVerified: false, providerWrites: 0 };
  const digest = createHash("sha256").update(JSON.stringify(manifest)).digest("hex");
  const name = "incident-assets-" + impact.incidentId;
  if (format === "JSON") return { filename: name + ".json",
    mime: "application/json", content: JSON.stringify({ ...manifest, digest }, null, 2),
    digest };
  if (format === "CSV") {
    const rows = [["deviceId", "importId", "externalId", "outcome",
      "matchBasis", "advisory", "observedAt"],
      ...impact.affectedDevices.map(x => [
        x.id, x.inventoryImportId, x.externalId,
        x.outcome, x.matchBasis, x.advisoryStatus, x.observedAt,
      ])];
    return { filename: name + ".csv", mime: "text/csv", digest,
      content: rows.map(row => row.map(csv).join(",")).join("\r\n") };
  }
  if (format !== "MARKDOWN") throw Error("ASSET_IMPACT_EXPORT_FORMAT_INVALID");
  const safe = (value: string) => value.replaceAll("|", "\\|")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  return { filename: name + ".md", mime: "text/markdown", digest,
    content: ["# Incident asset impact", "Organization: " + impact.organizationId,
      "Incident: " + impact.incidentId,
      "Devices: " + impact.affectedDevices.length,
      "Risk review: " + impact.reviewGate,
      "Remote isolation proven: NO", "Digest: " + digest, "",
      "## Affected inventory records",
      ...impact.affectedDevices.map(x => "- " + safe(x.externalId) +
        ": " + x.outcome + " (" + x.matchBasis + ")"),
      "", "## Operational handoffs",
      ...plan.actions.map(x => "- " + x.urgency + ": " +
        safe(x.kind) + " / device " + safe(x.deviceId)),
      "", "Inventory identification does not prove physical device identity.",
    ].join("\n") };
}
