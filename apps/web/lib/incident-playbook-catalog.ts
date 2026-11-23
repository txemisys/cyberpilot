import { createHash } from "node:crypto";

export const INCIDENT_TYPES = [
  "COMPROMISED_ACCOUNT", "PHISHING_CAMPAIGN", "RANSOMWARE",
  "LOST_DEVICE", "PAYMENT_FRAUD",
] as const;
export type IncidentType = typeof INCIDENT_TYPES[number];
export type IncidentSeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentState = "OPEN" | "TRIAGE" | "CONTAINMENT" | "RECOVERY" | "REVIEW" | "CLOSED";
export type StepState = "PENDING" | "IN_PROGRESS" | "BLOCKED" | "REPORTED_DONE" | "VERIFIED";
export type EvidenceVerdict = "OBSERVED" | "DECLARED" | "UNKNOWN" | "ERROR";
export type RiskClass = "READ_ONLY" | "EXTERNAL_CHANGE" | "DESTRUCTIVE" | "FINANCIAL";
export type IncidentRole = "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
export type IncidentCommand =
  | "START_TRIAGE" | "START_CONTAINMENT" | "START_RECOVERY"
  | "REQUEST_REVIEW" | "CLOSE" | "REOPEN" | "ASSIGN"
  | "COMMENT" | "STEP_START" | "STEP_BLOCK" | "STEP_REPORT"
  | "STEP_VERIFY" | "STEP_RESET" | "ATTACH_EVIDENCE" | "RECORD_APPROVAL";
export type IncidentStep = {
  id: string; title: string; objective: string;
  instructions: string[]; proofRequired: string[];
  providerCapability: string;
  risk: RiskClass; automationAllowed: false;
  requiresApproval: boolean; requiredEvidence: string[];
  fallback: string; suggestedOwner: string; targetMinutes: number;
};
export type IncidentPlaybook = {
  id: IncidentType; version: 1; title: string; severity: IncidentSeverity;
  description: string; immediateSafety: string[];
  escalation: string[]; steps: IncidentStep[];
  scopeLimitations: string[]; providerWrites: 0;
};
function step(id: string, title: string, objective: string, instructions: string[],
  proofRequired: string[], providerCapability: string, risk: RiskClass,
  requiredEvidence: string[], fallback: string, targetMinutes: number,
  suggestedOwner = "IT administrator"): IncidentStep {
  return { id, title, objective, instructions, proofRequired, providerCapability,
    risk, automationAllowed: false, requiresApproval: risk !== "READ_ONLY",
    requiredEvidence, fallback, suggestedOwner, targetMinutes };
}
const account: IncidentPlaybook = {
  id: "COMPROMISED_ACCOUNT", version: 1,
  title: "Compromised Microsoft 365 account", severity: "CRITICAL",
  description: "Guide identity containment, mailbox review and independently verified access recovery.",
  immediateSafety: [
    "Verify the incident reporter using an independent trusted channel.",
    "Preserve sign-in evidence before changes when safe and permitted.",
    "Use a clean administrative session and avoid relying on the suspected account.",
  ],
  escalation: [
    "Escalate immediately if a privileged identity or multiple users are affected.",
    "Consider legal/privacy notification assessment if personal data exposure is suspected.",
  ],
  scopeLimitations: [
    "A sign-in log may be unavailable because of licensing, retention or Graph permissions.",
    "Revoking sessions does not prove access has ended across all services.",
    "A reported password reset is not independent verification.",
  ],
  providerWrites: 0, steps: [
    step("verify-identity", "Confirm identity and suspected compromise",
      "Establish which exact principal and time range are involved.",
      ["Check tenant identity and principal identifier.", "Collect incident times in UTC.", "Cross-check the reporter through a trusted channel."],
      ["Principal ID from a trusted directory", "Timestamped confirmation of reporting source"],
      "directory-user-read", "READ_ONLY", ["identity", "report"], "Mark identity UNKNOWN until verified; do not revoke an unconfirmed user.", 10),
    step("sign-in-review", "Inspect sign-in history",
      "Identify anomalous accesses and their evidence limitations.",
      ["Review sign-in times, geography, client and device signals.", "Correlate with trusted user confirmation.", "Record retention gaps and license constraints."],
      ["Time-bounded sign-in export", "Attribution limitations documented"], "sign-in-log-read",
      "READ_ONLY", ["sign-in-log"], "Record UNKNOWN; absence of logs is not evidence of no compromise.", 20),
    step("revoke-sessions", "Revoke active sessions",
      "Request administrator-approved revocation and record verification.",
      ["Identify precise account.", "Have authorized administrator revoke sessions in Entra.", "Record provider acknowledgement and follow-up sign-ins."],
      ["Provider-side revocation confirmation", "Post-action sign-in review"], "session-revoke",
      "EXTERNAL_CHANGE", ["identity", "approval", "provider-result"], "Guide administrator; CyberPilot does not perform Graph writes.", 10),
    step("reset-password", "Reset password and recover access",
      "Reset credentials through a trusted process without exposing the password.",
      ["Validate recovery owner and identity.", "Reset through authorized identity system.", "Check MFA re-registration and secure recovery channels."],
      ["Provider password-reset completion record", "Trusted confirmation from administrator"], "password-reset",
      "EXTERNAL_CHANGE", ["approval", "provider-result"], "Record as pending if reset capability or permission is unavailable.", 20),
    step("mailbox-rules", "Review suspicious mailbox rules",
      "Identify forwarding, deletion and attacker persistence.",
      ["Inspect inbox rules including hidden or unexpected patterns.", "Review recent rule creation and owners.", "Escalate suspicious rules for separate approved removal."],
      ["Mailbox-rule inventory with timestamp", "Documented disposition per suspicious rule"], "mailbox-rule-read",
      "READ_ONLY", ["mailbox-rules"], "Mark mailbox inspection unavailable without mailbox-level authorization.", 20),
    step("forwarding", "Check mailbox forwarding",
      "Detect tenant-level and per-mailbox forwarding changes.",
      ["Review forwarding addresses and remote domain policies.", "Compare to authorized destinations.", "Request separate approval before changing configuration."],
      ["Forwarding configuration snapshot", "Business owner confirmation"], "mail-forwarding-read",
      "READ_ONLY", ["mail-forwarding"], "Do not infer that no forwarding exists from incomplete data.", 20),
    step("recovery", "Confirm recovery and follow-up",
      "Review residual access, MFA state and reporting duties.",
      ["Recheck sign-ins and suspicious rules.", "Validate account recovery with trusted user.", "Document outstanding unknown evidence and next review."],
      ["Post-recovery sign-in evidence", "Documented incident review"], "sign-in-log-read",
      "READ_ONLY", ["sign-in-log", "review"], "Keep incident in REVIEW if independent recovery checks are unavailable.", 60),
  ],
};
const phishing: IncidentPlaybook = {
  id: "PHISHING_CAMPAIGN", version: 1,
  title: "Phishing campaign", severity: "HIGH",
  description: "Scope messages and recipients, distinguish delivery from clicks and plan safe containment.",
  immediateSafety: ["Capture a sanitized sample without activating URLs or attachments.",
    "Use an out-of-band channel for high-risk user reporting."],
  escalation: ["Escalate if privileged users clicked or supplied credentials.",
    "Escalate suspected payment redirection to finance independently."],
  scopeLimitations: ["Message trace does not necessarily report clicks.",
    "A sender block does not prove copies already delivered are removed.",
    "Bulk purge must be authorized and verified by provider telemetry."],
  providerWrites: 0, steps: [
    step("sample", "Establish campaign indicators", "Normalize message identity without exposing harmful payloads.",
      ["Collect immutable message headers where permitted.", "Record sender, reply-to, URL domains and time window.", "Deduplicate campaign indicators."],
      ["Timestamped headers", "Original source provenance"], "message-read", "READ_ONLY",
      ["message-headers"], "Never fetch or open suspicious URLs automatically.", 10),
    step("recipients", "Identify impacted recipients", "Scope delivery with message trace or equivalent.",
      ["Search by immutable message ID and validated indicators.", "Distinguish delivered, quarantined and unknown.", "Record data-retention and licensing coverage."],
      ["Provider trace of recipients", "Scope and query timestamps"], "message-trace-read",
      "READ_ONLY", ["message-trace"], "Mark impacted population UNKNOWN without complete trace.", 25),
    step("clicks", "Identify clicked users when telemetry exists", "Confirm interactions only from independently observed signals.",
      ["Review licensed click and safe-links telemetry.", "Cross-check user report and URL correlation.", "Differentiate clicks from link presence."],
      ["Time-bounded click event log", "User-to-message correlation"], "url-click-telemetry",
      "READ_ONLY", ["click-telemetry"], "Report UNKNOWN, not zero clicked users.", 25),
    step("block", "Block sender and indicators", "Request authorized tenant-wide containment.",
      ["Confirm scope and potential false positives.", "Approve block changes with designated owner.", "Verify accepted policy changes and propagation."],
      ["Approval receipt", "Current block-policy readback"], "threat-block-write",
      "EXTERNAL_CHANGE", ["approval", "policy-readback"], "Guide administrator; no provider write is performed.", 15),
    step("purge", "Purge malicious messages", "Use least destructive approved search-and-purge workflow.",
      ["Preview exact candidate messages.", "Require administrator approval and a reversible approach when possible.", "Verify provider-side result and residual messages."],
      ["Approved target list", "Purge result with per-target failures"], "message-purge",
      "DESTRUCTIVE", ["approval", "message-trace", "provider-result"],
      "Do not mark purged if licensing, permission or post-action proof is absent.", 35),
    step("notify", "Notify affected users", "Deliver specific user guidance through an approved channel.",
      ["Review audience against delivery evidence.", "Draft a non-alarmist notice without suspicious links.", "Confirm delivery channel independently."],
      ["Audience record", "Delivery confirmation"], "notification-channel",
      "EXTERNAL_CHANGE", ["approval", "communication"], "Generate draft only; in-app drafting is not user delivery.", 25, "Security lead"),
    step("closure", "Verify campaign containment", "Document residual indicators and limitations.",
      ["Check later message trace and sign-in anomalies.", "Reconcile open user reports.", "Schedule follow-up for unverified outcomes."],
      ["Post-action trace", "Response review"], "message-trace-read",
      "READ_ONLY", ["review"], "Keep in review when any containment claim lacks independent proof.", 60),
  ],
};
const ransomware: IncidentPlaybook = {
  id: "RANSOMWARE", version: 1, title: "Ransomware response",
  severity: "CRITICAL",
  description: "Guide safe device containment, scope assessment, backup verification and recovery decisions.",
  immediateSafety: ["Treat active encryption as urgent; follow approved emergency response procedures.",
    "Avoid altering forensic evidence unnecessarily.", "Use clean communication channels and incident command."],
  escalation: ["Engage incident response specialist and legal counsel as appropriate.",
    "Escalate any observed spread, privileged compromise or backup compromise."],
  scopeLimitations: ["Asset inventory is not an EDR.", "Backup existence is not restore success.",
    "Offline analysis does not prove systems are isolated or encryption has stopped."],
  providerWrites: 0, steps: [
    step("triage", "Confirm indicators and incident command", "Identify reliable incident signals.",
      ["Collect timestamps and known device identifiers.", "Distinguish ransomware symptoms from verified malware classification.", "Record response owner and escalation."],
      ["Endpoint observation with provenance", "Named incident commander"], "endpoint-telemetry",
      "READ_ONLY", ["endpoint-observation"], "Mark detection unconfirmed if no trusted endpoint telemetry.", 10),
    step("isolate", "Isolate affected devices", "Coordinate explicit isolation with authorized EDR/MDM/network team.",
      ["Validate exact device identifier and blast radius.", "Obtain incident commander approval.", "Verify disconnection from trusted network telemetry."],
      ["Approved isolation target", "Provider-side network isolation acknowledgement"], "endpoint-isolation",
      "EXTERNAL_CHANGE", ["approval", "endpoint-observation", "provider-result"],
      "CyberPilot has no direct EDR/MDM isolation executor.", 10),
    step("scope", "Identify encryption scope", "Bound affected endpoints and data without speculative impact.",
      ["Correlate observed file modifications and alerts.", "List confirmed, suspected and unknown assets separately.", "Preserve evidence of affected shares and identities."],
      ["Timestamped endpoint inventory", "Documented affected-data estimate"], "endpoint-telemetry",
      "READ_ONLY", ["asset-inventory", "endpoint-observation"], "Report incomplete scope when telemetry is missing.", 30),
    step("backup", "Verify backup integrity", "Distinguish configured backup from tested restore.",
      ["Identify last known good immutable backup.", "Check backup isolation and compromise indicators.", "Plan restore to an isolated environment."],
      ["Backup inventory and timestamps", "Restore rehearsal result"], "backup-inventory-read",
      "READ_ONLY", ["backup-report", "restore-test"], "Mark RESTORE_NOT_VERIFIED until an actual restore is tested.", 30),
    step("contain", "Inspect persistence and access", "Reduce further spread through controlled administrative actions.",
      ["Review privileged access and recent configuration changes.", "Check remaining live alerts.", "Agree containment criteria with incident commander."],
      ["Control-plane change history", "Containment verification record"], "security-telemetry",
      "READ_ONLY", ["sign-in-log", "endpoint-observation"], "Do not declare contained based on an offline checklist.", 40),
    step("restore", "Authorize recovery", "Recover from validated backup while minimizing reinfection.",
      ["Approve recovery target and clean-room criteria.", "Restore and validate in isolation.", "Record integrity checks and staged reintegration."],
      ["Recovery authorization", "Verified restore checksum and application validation"], "backup-restore",
      "DESTRUCTIVE", ["approval", "restore-test"], "Recovery remains planned without operator-confirmed restore evidence.", 90),
    step("review", "Post-incident review", "Document verified impact and residual risks.",
      ["Record confirmed interruption and systems.", "Capture unknowns and recovery ownership.", "Schedule evidence-driven follow-up."],
      ["Incident postmortem", "Owner acceptance of open risks"], "incident-management",
      "READ_ONLY", ["review"], "Keep incident under review when critical restoration proof is missing.", 90),
  ],
};
const lost: IncidentPlaybook = {
  id: "LOST_DEVICE", version: 1, title: "Lost or stolen device",
  severity: "HIGH", description: "Coordinate device recovery, token revocation and privacy-safe wipe evaluation.",
  immediateSafety: ["Verify device ownership and reporter via independent channel.",
    "Avoid displaying live tracking data to unauthorized operators."],
  escalation: ["Escalate if device held privileged sessions or regulated data."],
  scopeLimitations: ["Device list alone does not prove MDM enrolment.",
    "A wipe command being accepted does not prove wipe completion."],
  providerWrites: 0, steps: [
    step("identify", "Verify device and custodian", "Match exact device identifier and approved custodian.",
      ["Identify serial, object ID and ownership.", "Check last reliable management contact.", "Document whether the device is corporate or personal."],
      ["Device inventory with source", "Custodian report"], "device-inventory-read",
      "READ_ONLY", ["asset-inventory"], "UNKNOWN when ownership or identifier cannot be established.", 15),
    step("sessions", "Review device sessions and access", "Bound potential data-access exposure.",
      ["Inspect authentication events by exact device or account.", "Review accessible applications and last sync.", "Document gaps in retained logs."],
      ["Sign-in timestamps", "Data access evidence"], "sign-in-log-read",
      "READ_ONLY", ["sign-in-log"], "No logs must never be interpreted as no access.", 20),
    step("tokens", "Revoke applicable tokens", "Request account/session containment through authorized admin.",
      ["Validate affected identities.", "Approve token revocation and record provider receipt.", "Verify follow-up sign-in observations."],
      ["Revocation acknowledgement", "Post-action access review"], "token-revocation",
      "EXTERNAL_CHANGE", ["approval", "provider-result"], "No direct Graph revocation performed.", 15),
    step("wipe", "Choose selective or full wipe", "Avoid deleting personal data without scoped authorization.",
      ["Verify enrolment and MDM capability.", "Choose selective corporate wipe wherever appropriate.", "Require explicit additional authorization for full destructive wipe."],
      ["Exact device and wipe type approved", "MDM completion readback"], "mdm-wipe",
      "DESTRUCTIVE", ["approval", "mdm-readback"],
      "If MDM permission/connection absent, retain pending and provide manual guidance.", 30),
    step("privacy", "Assess data exposure and notification", "Record evidence for regulatory and customer decisions.",
      ["Identify cached corporate data and encryption evidence.", "Determine if unauthorized access is observed or unknown.", "Consult privacy owner for notification decision."],
      ["Encryption posture evidence", "Privacy assessment decision"], "device-compliance-read",
      "READ_ONLY", ["asset-inventory", "review"], "Never infer encryption from an MDM label alone.", 60, "Privacy owner"),
    step("closure", "Reconcile device status", "Confirm completion or preserve unverified outcomes.",
      ["Review last MDM status and sign-in activity.", "Record residual missing capability.", "Document disposition and replacement controls."],
      ["Device state readback", "Final case review"], "mdm-status-read",
      "READ_ONLY", ["mdm-readback", "review"], "Keep REVIEW if wipe not independently observed.", 90),
  ],
};
const payments: IncidentPlaybook = {
  id: "PAYMENT_FRAUD", version: 1, title: "Payment fraud / business email compromise",
  severity: "CRITICAL", description: "Coordinate independent verification of banking changes, delegated access and mailbox persistence.",
  immediateSafety: ["Treat unverified banking changes as untrusted.",
    "Confirm instructions through a pre-established telephone number, never from the suspicious message."],
  escalation: ["Urgently notify authorized finance/banking contacts if a transfer is at risk.",
    "Preserve transaction identifiers and consider fraud reporting obligations."],
  scopeLimitations: ["CyberPilot does not query bank transaction systems.",
    "Email-domain alignment does not authenticate a bank-account-change request."],
  providerWrites: 0, steps: [
    step("request", "Capture suspicious payment request", "Identify exact invoice and payment-change indicators.",
      ["Record supplier and invoice reference in a restricted workspace.", "Preserve headers without storing account credentials.", "Identify requester and approval trail."],
      ["Source message provenance", "Invoice or change-request reference"], "message-read",
      "READ_ONLY", ["message-headers"], "Do not store full banking details in free-text incident notes.", 10, "Finance owner"),
    step("verify-bank", "Independently verify banking change", "Reject email-only validation of financial instructions.",
      ["Use previously verified supplier phone contact.", "Check approved change-control and dual authorization.", "Record decision without exposing full account number."],
      ["Verified out-of-band callback record", "Dual-approval reference"], "finance-change-control",
      "FINANCIAL", ["approval", "out-of-band-confirmation"],
      "Block payment until independent verification is documented.", 10, "Finance owner"),
    step("mail-rules", "Review mailbox rules and forwarding", "Find attacker-created routing or deletion patterns.",
      ["Inspect both delegated and recipient mailboxes when authorized.", "Review forwarding and rule history.", "Flag suspicious rules for separately approved removal."],
      ["Mailbox configuration snapshot", "Rule-change timeline"], "mailbox-rule-read",
      "READ_ONLY", ["mailbox-rules", "mail-forwarding"], "Mark UNKNOWN without mailbox authorization.", 25),
    step("delegates", "Review delegate access", "Check unauthorized mailbox and finance delegation.",
      ["Inspect mailbox delegates and application permissions.", "Compare membership to business authorization.", "Escalate discrepancies; preserve pre-change snapshot."],
      ["Delegated-access inventory", "Business owner approval"], "mailbox-delegation-read",
      "READ_ONLY", ["delegate-access"], "Do not infer absence of delegation from missing API data.", 30),
    step("bank", "Coordinate banking response", "Engage bank fraud channel if funds may already have moved.",
      ["Contact bank via independently verified number.", "Record case and transaction references.", "Follow bank advice and legal reporting process."],
      ["Bank fraud case reference", "Authorized finance escalation"], "banking-operations",
      "FINANCIAL", ["approval", "bank-confirmation"],
      "CyberPilot cannot reverse payments or validate bank response.", 15, "Finance owner"),
    step("communications", "Review impersonation and affected parties", "Avoid repeated fraud through legitimate notifications.",
      ["Use out-of-band supplier communication.", "Record recipients of false instructions.", "Request follow-up fraud-awareness action."],
      ["Approved communication", "Delivery receipt"], "notification-channel",
      "EXTERNAL_CHANGE", ["approval", "communication"], "Draft-only; no direct message delivery.", 35, "Finance owner"),
    step("closure", "Reconcile approved financial outcome", "Do not declare loss prevented without external confirmation.",
      ["Confirm changed bank details have independent verification.", "Review mailbox and delegate status.", "Preserve unresolved amounts as UNKNOWN."],
      ["Finance signoff", "Email access review"], "finance-change-control",
      "READ_ONLY", ["review"], "CLOSE is a workflow decision, not proof of funds recovery.", 60, "Finance owner"),
  ],
};
export const INCIDENT_PLAYBOOKS: Readonly<Record<IncidentType, IncidentPlaybook>> = {
  COMPROMISED_ACCOUNT: account, PHISHING_CAMPAIGN: phishing,
  RANSOMWARE: ransomware, LOST_DEVICE: lost, PAYMENT_FRAUD: payments,
};
export function getIncidentPlaybook(type: IncidentType): IncidentPlaybook {
  const book: IncidentPlaybook | undefined = INCIDENT_PLAYBOOKS[type];
  if (!book) throw new Error("INCIDENT_TYPE_UNSUPPORTED");
  return structuredClone(book);
}
export function catalogIncidentPlaybooks() {
  return INCIDENT_TYPES.map(type => {
    const book = getIncidentPlaybook(type);
    return { id: book.id, version: book.version, title: book.title,
      severity: book.severity, steps: book.steps.length, providerWrites: 0 as const,
      capabilities: [...new Set(book.steps.map(s => s.providerCapability))],
      approvalSteps: book.steps.filter(s => s.requiresApproval).length,
      limitations: book.scopeLimitations };
  });
}
export function digestIncidentPlaybook(book: IncidentPlaybook): string {
  return createHash("sha256").update(JSON.stringify(book)).digest("hex");
}
export function evaluatePlaybookCapability(type: IncidentType,
  available: ReadonlySet<string>): Array<{
    stepId: string; capability: string; availability: "AVAILABLE" | "UNAVAILABLE";
    operationExecuted: false; safeFallback: string;
  }> {
  return getIncidentPlaybook(type).steps.map(s => ({
    stepId: s.id, capability: s.providerCapability,
    availability: available.has(s.providerCapability) ? "AVAILABLE" : "UNAVAILABLE",
    operationExecuted: false as const, safeFallback: s.fallback,
  }));
}
export function validateIncidentPlaybooks(): string[] {
  const faults: string[] = [];
  for (const type of INCIDENT_TYPES) {
    const book = INCIDENT_PLAYBOOKS[type];
    if (book.id !== type || book.version !== 1 || book.providerWrites !== 0)
      faults.push(type + ":CATALOG_INVALID");
    const ids = new Set<string>();
    for (const s of book.steps) {
      if (ids.has(s.id)) faults.push(type + ":DUPLICATE_STEP:" + s.id);
      ids.add(s.id);
      if (s.instructions.length < 2 || s.proofRequired.length < 1 ||
          s.targetMinutes < 1 || !s.fallback || s.automationAllowed !== false ||
          s.requiresApproval !== (s.risk !== "READ_ONLY"))
        faults.push(type + ":STEP_UNSAFE:" + s.id);
      if (s.risk !== "READ_ONLY" && !s.requiredEvidence.includes("approval"))
        faults.push(type + ":APPROVAL_EVIDENCE_MISSING:" + s.id);
    }
  }
  return faults;
}
