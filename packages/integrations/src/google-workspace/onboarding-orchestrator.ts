import { createHash } from "node:crypto";
import {
  CAPABILITIES,
  type GoogleCapability,
} from "./directory-contract";
import {
  GoogleLabError, newGoogleLabConnection,
  transitionGoogleLab, inspectGoogleLabEligibility,
  verifyGoogleLabEvents, verifyGoogleLabConnection,
  replayGoogleLabHistory, redactGoogleLabConnection,
  type GoogleLabCommand, type GoogleLabConnection,
  type GoogleLabEvent, type GoogleLabScope,
  type GoogleLabTransition, type GoogleLabPolicy,
} from "./onboarding-policy";

export type GoogleLabRepository = {
  createInitial(
    scope: GoogleLabScope, state: GoogleLabConnection,
  ): Promise<GoogleLabConnection>;
  getByOrganization(
    organizationId: string, connectionId: string,
  ): Promise<GoogleLabConnection | null>;
  getEventHead(
    organizationId: string, connectionId: string,
  ): Promise<GoogleLabEvent | null>;
  compareAndSwap(
    old: GoogleLabConnection, transition: GoogleLabTransition,
  ): Promise<GoogleLabConnection>;
  getEvents(
    organizationId: string, connectionId: string,
    offset: number, limit: number,
  ): Promise<GoogleLabEvent[]>;
  list(
    organizationId: string, offset: number, limit: number,
  ): Promise<GoogleLabConnection[]>;
};
export type GoogleLabCreateCommand = {
  connectionId: string;
  createdAt: string;
  requestKey: string;
};
export type GoogleLabListQuery = {
  offset: number;
  limit: number;
  includeRevoked: boolean;
  includeExpired: boolean;
  filterState: GoogleLabConnection["state"] | null;
};
export type GoogleLabAuditReport = {
  schema: "cyberpilot.google.lab.audit.report.v1";
  organizationId: string;
  connectionId: string;
  currentRevision: number;
  currentState: string;
  eventsRead: number;
  completeHistory: boolean;
  chainVerified: boolean;
  stateVerified: boolean;
  replayResult: "CONSISTENT" | "INCOMPLETE" | "INVALID";
  issues: string[];
  headEventDigest: string | null;
  connectionDigest: string;
  observedAt: string;
  reportDigest: string;
  customerConsentLegallyAttested: false;
  googleProviderConnected: false;
  connectionTokensExported: false;
};
export type GoogleLabQueryResult = {
  organizationId: string;
  items: ReturnType<typeof redactGoogleLabConnection>[];
  offset: number;
  limit: number;
  nextOffset: number | null;
  filteredRows: number;
  sourceRows: number;
  providerApiRequests: 0;
  secretsReturned: false;
  crossTenantResultsPossible: false;
};
export type GoogleLabOperatorSummary = {
  schema: "cyberpilot.google.lab.operator.summary.v1";
  organizationId: string;
  connectionId: string;
  state: string;
  revision: number;
  capabilities: Array<{
    capability: GoogleCapability;
    eligibleForFixture: boolean;
    deniedReason: string | null;
    realProviderAccessible: false;
  }>;
  warnings: string[];
  suggestedCommands: Array<{
    command: GoogleLabCommand["type"];
    reason: string;
    wouldCallGoogle: false;
  }>;
  adminConsentVerified: false;
  googleLiveEnabled: false;
  automatedRemediationEnabled: false;
  accountWrites: 0;
};
export type GoogleLabTransitionReceipt = {
  schema: "cyberpilot.google.lab.transition.receipt.v1";
  organizationId: string;
  connectionId: string;
  revision: number;
  state: string;
  eventDigest: string;
  connectionDigest: string;
  command: GoogleLabCommand["type"];
  actorUserId: string;
  nextAction: "USE_FIXTURES" | "ISSUE_NEW_CHALLENGE" |
    "REVIEW_REVOKED_STATE" | "CHECK_STATUS";
  knownLimitations: string[];
  realGoogleConsent: false;
  liveGoogleRequests: 0;
  externalAccountWrites: 0;
};
const LIMITATIONS = [
  "The LAB onboarding state is a test artifact, not a Google OAuth token.",
  "An accepted synthetic challenge cannot authorize Admin SDK calls.",
  "The repository must provide an actual atomic compare-and-swap and audit transaction.",
  "A local hash is not an administrator signature or independent Google attestation.",
  "Expiry and revocation prevent future fixture eligibility but cannot revoke external tokens (none exist).",
  "Tenant isolation is enforced for every lookup and write by the repository.",
  "The software never infers a successful customer connection from a CI fixture.",
];
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function checkString(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^[A-Za-z0-9_-]{5,128}$/.test(value))
    throw new GoogleLabError("INVALID",
      "Invalid " + label + " identifier.");
  return value;
}
function date(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    throw new GoogleLabError("INVALID", "Valid UTC time required.");
  return new Date(value).toISOString();
}
function authorize(scope: GoogleLabScope, manager = false) {
  checkString(scope?.organizationId, "organization");
  checkString(scope?.actorUserId, "user");
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role) ||
      manager && !["OWNER", "ADMIN"].includes(scope.role))
    throw new GoogleLabError("FORBIDDEN",
      "Organization role cannot perform requested LAB operation.");
}
export function parseGoogleLabQuery(raw: unknown = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    throw new GoogleLabError("INVALID", "Invalid LAB list query.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(key => ![
    "offset", "limit", "includeRevoked", "includeExpired",
    "filterState",
  ].includes(key)))
    throw new GoogleLabError("INVALID", "Unsupported LAB list filter.");
  const offset = x.offset ?? 0, limit = x.limit ?? 20;
  if (typeof offset !== "number" ||
      !Number.isSafeInteger(offset) || offset < 0 ||
      offset > 100000)
    throw new GoogleLabError("INVALID", "Invalid LAB list offset.");
  if (typeof limit !== "number" ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100)
    throw new GoogleLabError("INVALID", "Invalid LAB list limit.");
  for (const field of ["includeRevoked", "includeExpired"])
    if (x[field] !== undefined && typeof x[field] !== "boolean")
      throw new GoogleLabError("INVALID", "Invalid LAB visibility flag.");
  if (x.filterState !== undefined && x.filterState !== null &&
      !["NOT_CONFIGURED", "CHALLENGE_ISSUED", "CONSENT_DENIED",
        "CONNECTED_LAB", "SUSPENDED", "REVOKED", "EXPIRED"]
        .includes(String(x.filterState)))
    throw new GoogleLabError("INVALID", "Unknown LAB connection state.");
  return {
    offset, limit,
    includeRevoked: x.includeRevoked === true,
    includeExpired: x.includeExpired === true,
    filterState: x.filterState ?? null,
  } as GoogleLabListQuery;
}
export function parseLabCreate(value: unknown): GoogleLabCreateCommand {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new GoogleLabError("INVALID",
      "LAB creation expects an object.");
  const data = value as Record<string, unknown>;
  if (Object.keys(data).some(key => ![
    "connectionId", "createdAt", "requestKey",
  ].includes(key)))
    throw new GoogleLabError("INVALID",
      "Unknown LAB creation command.");
  return {
    connectionId: checkString(data.connectionId, "connection"),
    createdAt: date(data.createdAt),
    requestKey: checkString(data.requestKey, "request key"),
  };
}
export function createGoogleLabReceipt(
  transition: GoogleLabTransition,
): GoogleLabTransitionReceipt {
  const connection = transition.connection;
  const command = transition.event.type;
  let nextAction: GoogleLabTransitionReceipt["nextAction"] =
    "CHECK_STATUS";
  if (command === "ACCEPT_LAB" || command === "RESUME")
    nextAction = "USE_FIXTURES";
  if (command === "DENY_CONSENT" || command === "EXPIRE" ||
      command === "REVOKE")
    nextAction = "REVIEW_REVOKED_STATE";
  if (command === "ROTATE_CHALLENGE" ||
      command === "ISSUE_CHALLENGE")
    nextAction = "ISSUE_NEW_CHALLENGE";
  return {
    schema: "cyberpilot.google.lab.transition.receipt.v1",
    organizationId: connection.organizationId,
    connectionId: connection.id,
    revision: connection.revision,
    state: connection.state,
    eventDigest: transition.event.digest,
    connectionDigest: connection.stateDigest,
    command, actorUserId: transition.event.actorUserId,
    nextAction,
    knownLimitations: [...LIMITATIONS],
    realGoogleConsent: false,
    liveGoogleRequests: 0, externalAccountWrites: 0,
  };
}
export function inspectLabOperatorSummary(
  connection: GoogleLabConnection,
  scope: GoogleLabScope, at: string,
): GoogleLabOperatorSummary {
  const allowed = inspectGoogleLabEligibility(connection,
    scope, at, [...CAPABILITIES]);
  const capabilities = CAPABILITIES.map(capability => ({
    capability,
    eligibleForFixture: allowed.allowedCapabilities.includes(capability),
    deniedReason: allowed.allowedCapabilities.includes(capability) ?
      null : allowed.reasons[0] ?? "LAB_CAPABILITY_NOT_ALLOWED",
    realProviderAccessible: false as const,
  }));
  const commands: GoogleLabOperatorSummary["suggestedCommands"] = [];
  const propose = (command: GoogleLabCommand["type"],
    reason: string) => commands.push({
      command, reason, wouldCallGoogle: false,
    });
  switch (allowed.effectiveState) {
    case "NOT_CONFIGURED":
    case "CONSENT_DENIED":
    case "REVOKED":
    case "EXPIRED":
      propose("ISSUE_CHALLENGE", "Initiate a new offline LAB challenge.");
      break;
    case "CHALLENGE_ISSUED":
      propose("ACCEPT_LAB", "Use the original nonce in a bounded local fixture flow.");
      propose("DENY_CONSENT", "Explicitly reject the simulation request.");
      break;
    case "CONNECTED_LAB":
      propose("SUSPEND", "Temporarily disable fixture access.");
      propose("REVOKE", "Revoke the LAB connection.");
      propose("CHANGE_CAPABILITIES", "Narrow previously requested LAB scopes.");
      break;
    case "SUSPENDED":
      propose("RESUME", "Restore permitted fixture capabilities if not expired.");
      propose("REVOKE", "Permanently invalidate this LAB authorization.");
      break;
  }
  return {
    schema: "cyberpilot.google.lab.operator.summary.v1",
    organizationId: connection.organizationId,
    connectionId: connection.id, state: allowed.effectiveState,
    revision: connection.revision,
    capabilities,
    warnings: [...allowed.reasons, ...LIMITATIONS],
    suggestedCommands: commands,
    adminConsentVerified: false, googleLiveEnabled: false,
    automatedRemediationEnabled: false, accountWrites: 0,
  };
}
export class GoogleLabOnboardingService {
  constructor(
    private readonly repository: GoogleLabRepository,
    private readonly rawPolicy: Partial<GoogleLabPolicy> = {},
  ) {}
  async create(scope: GoogleLabScope, raw: unknown) {
    authorize(scope, true);
    const command = parseLabCreate(raw);
    const initial = newGoogleLabConnection(scope,
      command.connectionId, command.createdAt);
    const stored = await this.repository.createInitial(scope, initial);
    if (stored.organizationId !== scope.organizationId ||
        stored.id !== command.connectionId ||
        stored.revision !== 0 ||
        !verifyGoogleLabConnection(stored).valid)
      throw new GoogleLabError("CONFLICT",
        "LAB store violated connection creation contract.");
    return {
      connection: redactGoogleLabConnection(stored),
      stateDigest: stored.stateDigest,
      created: true, googleApiCalls: 0 as const,
      realConsentVerified: false as const,
    };
  }
  async get(scope: GoogleLabScope, id: string,
    at = new Date().toISOString()) {
    authorize(scope);
    const connection = await this.require(scope, id);
    return {
      connection: redactGoogleLabConnection(connection),
      summary: inspectLabOperatorSummary(connection, scope, at),
      providerLive: false as const,
    };
  }
  private async require(scope: GoogleLabScope, id: string) {
    const connectionId = checkString(id, "connection");
    const connection = await this.repository.getByOrganization(
      scope.organizationId, connectionId);
    if (!connection || connection.organizationId !==
        scope.organizationId || connection.id !== connectionId)
      throw new GoogleLabError("MISSING",
        "Google LAB connection not found in this organization.");
    if (!verifyGoogleLabConnection(connection).valid)
      throw new GoogleLabError("CONFLICT",
        "Persisted LAB connection failed integrity check.");
    return connection;
  }
  async mutate(scope: GoogleLabScope, command: GoogleLabCommand) {
    authorize(scope, true);
    const connection = await this.require(scope, command.connectionId);
    const last = await this.repository.getEventHead(
      scope.organizationId, connection.id);
    const transition = transitionGoogleLab(
      connection, scope, command, last, this.rawPolicy);
    const stored = await this.repository.compareAndSwap(
      connection, transition);
    if (stored.organizationId !== scope.organizationId ||
        stored.revision !== transition.connection.revision ||
        stored.stateDigest !== transition.connection.stateDigest)
      throw new GoogleLabError("CONFLICT",
        "Stored LAB state differs from verified CAS transition.");
    return {
      receipt: createGoogleLabReceipt(transition),
      connection: redactGoogleLabConnection(stored),
      realProviderContacted: false as const,
    };
  }
  async list(scope: GoogleLabScope,
    rawQuery: unknown = {}): Promise<GoogleLabQueryResult> {
    authorize(scope);
    const query = parseGoogleLabQuery(rawQuery);
    const rows = await this.repository.list(
      scope.organizationId, query.offset, query.limit + 1);
    if (rows.length > query.limit + 1 ||
        rows.some(row => row.organizationId !== scope.organizationId))
      throw new GoogleLabError("CONFLICT",
        "LAB list violated tenant boundary or requested pagination.");
    const visible = rows.slice(0, query.limit).filter(row =>
      (query.includeRevoked || row.state !== "REVOKED") &&
      (query.includeExpired || row.state !== "EXPIRED") &&
      (!query.filterState || row.state === query.filterState));
    if (visible.some(x => !verifyGoogleLabConnection(x).valid))
      throw new GoogleLabError("CONFLICT",
        "LAB list contained invalid persisted state.");
    return {
      organizationId: scope.organizationId,
      items: visible.map(redactGoogleLabConnection),
      offset: query.offset, limit: query.limit,
      nextOffset: rows.length > query.limit ?
        query.offset + query.limit : null,
      sourceRows: rows.length,
      filteredRows: visible.length,
      providerApiRequests: 0,
      secretsReturned: false,
      crossTenantResultsPossible: false,
    };
  }
  async audit(scope: GoogleLabScope, id: string,
    at: string): Promise<GoogleLabAuditReport> {
    authorize(scope);
    const connection = await this.require(scope, id);
    const timestamp = date(at);
    const events = await this.repository.getEvents(
      scope.organizationId, connection.id,
      0, Math.min(connection.revision, 10000));
    if (events.length > Math.min(connection.revision, 10000) ||
        events.some(event => event.organizationId !==
          scope.organizationId ||
          event.connectionId !== connection.id))
      throw new GoogleLabError("CONFLICT",
        "LAB audit returned data outside organization scope.");
    const history = verifyGoogleLabEvents(connection, events);
    const completeHistory = events.length === connection.revision;
    const issues = [...history.issues];
    if (!completeHistory)
      issues.push("HISTORY_NOT_FULLY_READ");
    const replay = events.length ?
      replayGoogleLabHistory(newGoogleLabConnection({
        organizationId: connection.organizationId,
        actorUserId: connection.createdByUserId,
        role: "ADMIN",
      }, connection.id, connection.createdAt), events) : null;
    if (replay && !replay.valid)
      issues.push(...replay.issues);
    const consistent = completeHistory &&
      history.valid && (replay?.valid ?? true);
    const canonical = {
      schema: "cyberpilot.google.lab.audit.report.v1" as const,
      organizationId: scope.organizationId,
      connectionId: connection.id,
      currentRevision: connection.revision,
      currentState: connection.state,
      eventsRead: events.length, completeHistory,
      chainVerified: consistent,
      stateVerified: verifyGoogleLabConnection(connection).valid,
      replayResult: !completeHistory ?
        "INCOMPLETE" as const : consistent ?
          "CONSISTENT" as const : "INVALID" as const,
      issues,
      headEventDigest: events.at(-1)?.digest ?? null,
      connectionDigest: connection.stateDigest,
      observedAt: timestamp,
      customerConsentLegallyAttested: false as const,
      googleProviderConnected: false as const,
      connectionTokensExported: false as const,
    };
    return { ...canonical, reportDigest: hash(canonical) };
  }
  async eligibility(scope: GoogleLabScope, id: string,
    at: string, requested: GoogleCapability[]) {
    authorize(scope);
    const connection = await this.require(scope, id);
    return inspectGoogleLabEligibility(connection,
      scope, at, requested);
  }
}
export function verifyGoogleLabAuditReport(report: GoogleLabAuditReport) {
  const { reportDigest, ...canonical } = report;
  const issues: string[] = [];
  if (hash(canonical) !== reportDigest)
    issues.push("LAB audit report content altered.");
  if (report.customerConsentLegallyAttested ||
      report.googleProviderConnected ||
      report.connectionTokensExported)
    issues.push("LAB audit falsely claims external authorization.");
  if (report.replayResult === "CONSISTENT" &&
      (!report.completeHistory ||
       !report.chainVerified ||
       !report.stateVerified ||
       report.issues.length > 0))
    issues.push("Audit verdict contradicts reconciliation evidence.");
  return { valid: issues.length === 0, issues };
}
