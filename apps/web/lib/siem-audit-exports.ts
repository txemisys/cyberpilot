import { createHash } from "node:crypto";
import type { PortableAuditEvent, SiemFormat } from "./siem-audit-interchange-domain";
import type { SiemPage } from "./siem-audit-cursor-and-continuity";
export type SiemArtifact = { schema: "cyberpilot.siem.export.v1";
  format: SiemFormat; filename: string; mime: string; content: string;
  pageDigest: string; artifactDigest: string; rowCount: number;
  externallyDelivered: false; deliveryReceipt: null; source: "PERSISTED_AUDIT_PAGE";
};
const formula = /^[=+\-@\t\r]/;
const csv = (input: string | number | boolean | null) => {
  const raw = String(input ?? "");
  const safe = formula.test(raw) ? "'" + raw : raw;
  return '"' + safe.replaceAll('"', '""').replaceAll("\n", " ")
    .replaceAll("\r", " ") + '"';
};
const ascii = (value: string) => value.normalize("NFKC")
  .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
  .replace(/\\/g, "\\\\").replace(/\|/g, "\\|")
  .replace(/=/g, "\\=").slice(0, 512);
function ecs(event: PortableAuditEvent) {
  const severity = { INFORMATIONAL: 1, LOW: 2, MEDIUM: 4,
    HIGH: 6, CRITICAL: 8 }[event.severity];
  const ecsCategory = ({ AUTHENTICATION: "authentication", AUTHORIZATION: "iam",
    CONSENT: "iam", REMEDIATION: "configuration", EVIDENCE: "configuration",
    INCIDENT: "intrusion_detection", INTEGRATION: "configuration",
    CONFIGURATION: "configuration", GENERAL: "configuration" } as const)[event.category];
  return { "@timestamp": event.occurredAt,
    "ecs": { version: "8.11.0" },
    "event": { id: event.eventId,
      kind: "event", category: [ecsCategory],
      type: ["info"], action: event.action, severity,
      provider: "cyberpilot", dataset: "cyberpilot.audit", module: "cyberpilot" },
    "observer": { vendor: "CyberPilot", product: "CyberPilot" },
    "organization": { id: event.organizationId },
    "user": event.actorReference ? { id: event.actorReference } : {},
    "source": { domain: "cyberpilot-persistent-audit" },
    "cyberpilot": { resourceType: event.resourceType,
      resourceReference: event.resourceReference,
      actorType: event.actorType, confidence: event.confidence,
      metadata: event.metadataFields, redactedFields: event.redactedFields,
      providerActionProven: false, delivered: false },
    "message": event.action + " on " + event.resourceType,
  };
}
function cef(event: PortableAuditEvent) {
  const numericSeverity = { INFORMATIONAL: 1, LOW: 3, MEDIUM: 5,
    HIGH: 8, CRITICAL: 10 }[event.severity];
  const timestamp = new Date(event.occurredAt).getTime();
  const extension = [
    "rt=" + timestamp,
    "externalId=" + ascii(event.eventId),
    "cs1Label=OrganizationId", "cs1=" + ascii(event.organizationId),
    "cs2Label=ResourceType", "cs2=" + ascii(event.resourceType),
    "cs3Label=AuditConfidence", "cs3=" + ascii(event.confidence),
    "cs4Label=ActorType", "cs4=" + ascii(event.actorType),
    "cs5Label=Delivery", "cs5=UNVERIFIED",
    "cat=" + ascii(event.category),
    "act=" + ascii(event.action),
    "outcome=UNKNOWN",
    ...(event.actorReference ? ["suser=" + ascii(event.actorReference)] : []),
    ...(event.resourceReference ? ["cs6Label=ResourceReference",
      "cs6=" + ascii(event.resourceReference)] : []),
    ...Object.entries(event.metadataFields).slice(0, 2).flatMap(([k, v], index) => [
      "flexString" + (index + 1) + "Label=" + ascii(k),
      "flexString" + (index + 1) + "=" + ascii(String(v)),
    ]),
  ].join(" ");
  return "CEF:0|CyberPilot|CyberPilot|1|AUDIT_EVENT|" +
    ascii(event.action) + "|" + numericSeverity + "|" + extension;
}
export function buildSiemExport(page: SiemPage, format: SiemFormat): SiemArtifact {
  if (!page.integrity.valid || page.events.length > page.selection.limit ||
      !["JSONL", "ECS", "CEF", "CSV"].includes(format))
    throw Error("SIEM_EXPORT_PAGE_INVALID");
  if (page.events.some(x => x.organizationId !== page.organizationId ||
      x.transmissionVerified !== false || x.actualRemediationProven !== false))
    throw Error("SIEM_EXPORT_UNSUPPORTED_CLAIMS");
  const head = "cyberpilot-audit-" +
    page.evaluatedAt.slice(0, 10) + "-" + page.pageDigest.slice(0, 12);
  let mime = "application/x-ndjson";
  let ext = ".jsonl";
  let content: string;
  if (format === "JSONL") content = page.events.map(x => JSON.stringify(x)).join("\n");
  else if (format === "ECS") content = page.events.map(x => JSON.stringify(ecs(x))).join("\n");
  else if (format === "CEF") {
    mime = "text/plain"; ext = ".cef";
    content = page.events.map(cef).join("\n");
  } else {
    mime = "text/csv"; ext = ".csv";
    const columns = ["eventId", "occurredAt", "organizationId", "action",
      "category", "severity", "actorType", "actorReference", "resourceType",
      "resourceReference", "confidence", "redactedFields", "metadata"];
    const rows = page.events.map(event => [
      event.eventId, event.occurredAt, event.organizationId,
      event.action, event.category, event.severity, event.actorType,
      event.actorReference ?? "", event.resourceType,
      event.resourceReference ?? "", event.confidence,
      String(event.redactedFields), JSON.stringify(event.metadataFields),
    ]);
    content = [columns.map(csv).join(","), ...rows.map(x =>
      x.map(csv).join(","))].join("\r\n");
  }
  const digest = createHash("sha256").update(content).digest("hex");
  return { schema: "cyberpilot.siem.export.v1", format,
    filename: head + ext, mime, content, pageDigest: page.pageDigest,
    artifactDigest: digest, rowCount: page.events.length,
    externallyDelivered: false, deliveryReceipt: null,
    source: "PERSISTED_AUDIT_PAGE" };
}
export type SiemDataQuality = {
  schema: "cyberpilot.siem.quality.v1"; organizationId: string;
  evaluatedAt: string; total: number; malformed: number;
  partiallyRedacted: number; allRedacted: number;
  nullActors: number; missingResources: number; duplicateActions: number;
  actions: Array<{ action: string; count: number; lastSeen: string }>;
  alertCandidates: Array<{ eventId: string; reason: string; severity: string }>;
  noSecurityImprovementImplied: true; allExternalAcknowledgementsAbsent: true;
};
export function inspectSiemPageQuality(page: SiemPage): SiemDataQuality {
  const actions = new Map<string, { count: number; lastSeen: string }>();
  const alertCandidates: SiemDataQuality["alertCandidates"] = [];
  for (const event of page.events) {
    const existing = actions.get(event.action);
    actions.set(event.action, { count: (existing?.count ?? 0) + 1,
      lastSeen: event.occurredAt > (existing?.lastSeen ?? "") ?
        event.occurredAt : existing!.lastSeen });
    if (event.severity === "HIGH" || event.severity === "CRITICAL")
      alertCandidates.push({ eventId: event.eventId,
        reason: "HIGH_IMPACT_AUDIT_ACTION", severity: event.severity });
    if (event.malformedMetadata)
      alertCandidates.push({ eventId: event.eventId,
        reason: "MALFORMED_AUDIT_METADATA", severity: "MEDIUM" });
  }
  return { schema: "cyberpilot.siem.quality.v1",
    organizationId: page.organizationId, evaluatedAt: page.evaluatedAt,
    total: page.events.length,
    malformed: page.events.filter(x => x.confidence === "MALFORMED").length,
    partiallyRedacted: page.events.filter(x => x.redactedFields > 0).length,
    allRedacted: page.events.filter(x => x.redactedFields > 0 &&
      Object.keys(x.metadataFields).length === 0).length,
    nullActors: page.events.filter(x => x.actorReference === null).length,
    missingResources: page.events.filter(x => x.resourceReference === null).length,
    duplicateActions: page.events.length - actions.size,
    actions: [...actions.entries()].map(([action, count]) => ({
      action, ...count })).sort((a, b) => b.count - a.count || a.action.localeCompare(b.action)),
    alertCandidates: alertCandidates.slice(0, 100),
    noSecurityImprovementImplied: true,
    allExternalAcknowledgementsAbsent: true };
}
export type SiemForwardingReadiness = {
  schema: "cyberpilot.siem.forwarding-readiness.v1";
  organizationId: string; verdict: "NOT_CONNECTED" | "REQUIRES_REVIEW" | "EXPORT_READY";
  findings: string[]; exportFormats: SiemFormat[];
  providerCredentialsPresent: false; deliveryConfigured: false;
  deliveryExecuted: false; receiverAcknowledged: false;
};
export function inspectSiemForwardingReadiness(page: SiemPage): SiemForwardingReadiness {
  const quality = inspectSiemPageQuality(page), findings: string[] = [];
  if (!page.integrity.valid) findings.push("PAGE_INTEGRITY_INVALID");
  if (page.hasMore) findings.push("EXPORT_WINDOW_PARTIAL");
  if (quality.malformed) findings.push("MALFORMED_EVENTS_PRESENT");
  if (quality.total === 0) findings.push("NO_EVENTS_IN_WINDOW");
  if (quality.partiallyRedacted) findings.push("REDACTION_APPLIED_REVIEW_FIELDS");
  return { schema: "cyberpilot.siem.forwarding-readiness.v1",
    organizationId: page.organizationId,
    verdict: "NOT_CONNECTED", findings, exportFormats: ["JSONL", "ECS", "CEF", "CSV"],
    providerCredentialsPresent: false, deliveryConfigured: false,
    deliveryExecuted: false, receiverAcknowledged: false };
}
