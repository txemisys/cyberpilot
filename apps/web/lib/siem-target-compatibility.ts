import type { PortableAuditEvent } from "./siem-audit-interchange-domain";
import type { SiemPage } from "./siem-audit-cursor-and-continuity";
export const SIEM_TARGETS = ["SPLUNK", "MICROSOFT_SENTINEL", "DATADOG"] as const;
export type SiemTarget = typeof SIEM_TARGETS[number];
export type TargetPreparation = {
  schema: "cyberpilot.siem.target-preparation.v1";
  organizationId: string; target: SiemTarget;
  compatibleFormats: string[]; recommendedFormat: string;
  eventCount: number; acceptedForManualReview: boolean;
  warnings: string[]; requiredConfiguration: string[];
  requiredExternalVerification: string[]; customFieldMapping: Record<string, string>;
  apiDeliveryAttempted: false; tokenConfigured: false;
  remoteAckObserved: false; transmissionResult: "NOT_ATTEMPTED";
};
const contracts: Record<SiemTarget, {
  preferred: string; accepted: string[]; fields: Record<string, string>;
  config: string[]; verification: string[];
}> = {
  SPLUNK: {
    preferred: "JSONL", accepted: ["JSONL", "CSV", "CEF"],
    fields: { eventId: "event_id", occurredAt: "_time",
      action: "action", severity: "severity", category: "category",
      organizationId: "org_id", resourceType: "resource_type" },
    config: ["HEC endpoint and scoped token", "Dedicated source/sourcetype",
      "Retention and index-access policy", "Secret rotation and rollback"],
    verification: ["Confirm HEC response per batch", "Query event ID in destination",
      "Verify target index and timestamp", "Reconcile missing/duplicate IDs"],
  },
  MICROSOFT_SENTINEL: {
    preferred: "ECS", accepted: ["ECS", "JSONL", "CEF"],
    fields: { eventId: "EventId", occurredAt: "TimeGenerated",
      action: "Action", severity: "Severity", category: "Category",
      organizationId: "OrganizationId", resourceType: "ResourceType" },
    config: ["Authorized DCR/stream association", "Regional Log Analytics workspace",
      "Ingestion identity and RBAC", "Schema and retention confirmation"],
    verification: ["Validate ingestion acceptance result", "Query custom table by event ID",
      "Verify workspace region and access", "Reconcile partial failures"],
  },
  DATADOG: {
    preferred: "JSONL", accepted: ["JSONL", "ECS"],
    fields: { eventId: "event.id", occurredAt: "timestamp",
      action: "event.action", severity: "status", category: "service",
      organizationId: "organization.id", resourceType: "resource.type" },
    config: ["Approved logs intake site and region", "Dedicated restricted API key",
      "Sensitive field scrubbing", "Retention and index routing"],
    verification: ["Confirm destination intake acknowledgement",
      "Search by generated event ID", "Verify regional endpoint selection",
      "Reconcile ingested counts and delays"],
  },
};
const limits = (event: PortableAuditEvent) => {
  const cautions: string[] = [];
  if (event.confidence === "MALFORMED") cautions.push("MALFORMED_SOURCE_EVENT");
  if (event.confidence === "PARTIAL") cautions.push("PARTIAL_METADATA");
  if (event.metadataFields && Object.keys(event.metadataFields).length > 20)
    cautions.push("MANY_METADATA_FIELDS");
  if (event.resourceReference !== null) cautions.push("RESOURCE_REFERENCE_EXPORTED");
  if (event.actorReference !== null) cautions.push("PSEUDONYMIZED_ACTOR_PRESENT");
  return cautions;
};
export function prepareSiemTarget(page: SiemPage, target: SiemTarget): TargetPreparation {
  const contract = contracts[target];
  if (!contract) throw Error("SIEM_TARGET_UNKNOWN");
  if (!page.integrity.valid || page.events.some(x =>
      x.organizationId !== page.organizationId))
    throw Error("SIEM_TARGET_PAGE_UNTRUSTED");
  const warnings = [...new Set(page.events.flatMap(limits))];
  if (page.hasMore) warnings.push("PAGE_PARTIAL_CONTINUE_CURSOR");
  if (page.events.length === 0) warnings.push("NO_AUDIT_ROWS_SELECTED");
  if (page.events.some(x => x.actualRemediationProven !== false ||
      x.transmissionVerified !== false)) throw Error("SIEM_TARGET_FALSE_ASSURANCE");
  return {
    schema: "cyberpilot.siem.target-preparation.v1",
    organizationId: page.organizationId, target,
    compatibleFormats: contract.accepted, recommendedFormat: contract.preferred,
    eventCount: page.events.length,
    acceptedForManualReview: page.events.length > 0 && page.integrity.valid,
    warnings, requiredConfiguration: contract.config,
    requiredExternalVerification: contract.verification,
    customFieldMapping: contract.fields,
    apiDeliveryAttempted: false, tokenConfigured: false,
    remoteAckObserved: false, transmissionResult: "NOT_ATTEMPTED",
  };
}
export function compareSiemTargetPreparations(page: SiemPage) {
  const profiles = SIEM_TARGETS.map(target => prepareSiemTarget(page, target));
  return { schema: "cyberpilot.siem.target-choices.v1" as const,
    organizationId: page.organizationId,
    formats: [...new Set(profiles.flatMap(p => p.compatibleFormats))].sort(),
    profiles, destinationsConnected: 0 as const,
    externalDeliveryVerified: false as const };
}
