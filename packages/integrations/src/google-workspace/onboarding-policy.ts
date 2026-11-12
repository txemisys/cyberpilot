import { createHash, timingSafeEqual } from "node:crypto";
import { CAPABILITIES, type GoogleCapability } from "./directory-contract";

/**
 * Explicit LAB consent is distinct from genuine OAuth administrator consent.
 * The state machine never mints access tokens or contacts Google APIs.
 */
export type GoogleLabState =
  "NOT_CONFIGURED" | "CHALLENGE_ISSUED" | "CONSENT_DENIED" |
  "CONNECTED_LAB" | "SUSPENDED" | "REVOKED" | "EXPIRED";
export type GoogleLabRole = "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
export type GoogleLabCommandType =
  "ISSUE_CHALLENGE" | "DENY_CONSENT" | "ACCEPT_LAB" |
  "SUSPEND" | "RESUME" | "REVOKE" | "EXPIRE" |
  "ROTATE_CHALLENGE" | "CHANGE_CAPABILITIES";
export type GoogleLabScope = {
  organizationId: string;
  actorUserId: string;
  role: GoogleLabRole;
};
export type GoogleLabPolicy = {
  maxChallengeAgeSeconds: number;
  maxConnectionAgeDays: number;
  maxEvents: number;
  maxChallengeAttempts: number;
  requireIndependentReviewerForLive: true;
  allowRealGoogleOauth: false;
  allowExternalGoogleProvider: false;
  allowAccountWrites: false;
  customerConsentNotAttested: true;
};
export type GoogleLabChallenge = {
  challengeDigest: string;
  organizationId: string;
  requestedByUserId: string;
  requestedAt: string;
  expiresAt: string;
  requestDigest: string;
  usedAt: string | null;
  revokedAt: string | null;
  attempts: number;
  capabilitySet: GoogleCapability[];
  providerOrigin: "SYNTHETIC_FIXTURE";
  realGoogleOauthPerformed: false;
};
export type GoogleLabConnection = {
  schema: "cyberpilot.google.lab.connection.v1";
  id: string;
  organizationId: string;
  createdByUserId: string;
  revision: number;
  state: GoogleLabState;
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  challenge: GoogleLabChallenge | null;
  permittedCapabilities: GoogleCapability[];
  consentScope: "OFFLINE_LAB_SIMULATION";
  provider: "GOOGLE_WORKSPACE";
  credentialStored: false;
  liveProviderConnected: false;
  administratorConsentVerified: false;
  accountMutationEnabled: false;
  customerDeploymentApproved: false;
  stateDigest: string;
};
export type GoogleLabEvent = {
  schema: "cyberpilot.google.lab.event.v1";
  organizationId: string;
  connectionId: string;
  revision: number;
  type: GoogleLabCommandType;
  actorUserId: string;
  at: string;
  from: GoogleLabState;
  to: GoogleLabState;
  previousEventDigest: string | null;
  connectionDigest: string;
  challengeDigest: string | null;
  requestedCapabilityCount: number;
  explanationCode: string;
  realProviderContacted: false;
  privilegedActionPerformed: false;
  digest: string;
};
export type GoogleLabTransition = {
  connection: GoogleLabConnection;
  event: GoogleLabEvent;
  warnings: string[];
  sideEffects: {
    googleApiRequests: 0;
    oauthTokensGranted: 0;
    accountWrites: 0;
    customerConsentRecordedAsReal: false;
    requiresDatabaseTransaction: true;
  };
};
export type GoogleLabCommand = {
  type: GoogleLabCommandType;
  connectionId: string;
  expectedRevision: number;
  at: string;
  reason: string;
  challengeNonce?: string;
  requestedCapabilities?: GoogleCapability[];
  challengedAt?: string;
  previousEventDigest?: string | null;
  allowRealGoogle?: false;
};
export type GoogleLabAcceptance = {
  eligible: boolean;
  connectionId: string;
  organizationId: string;
  revision: number;
  effectiveState: GoogleLabState;
  allowedCapabilities: GoogleCapability[];
  blockedCapabilities: GoogleCapability[];
  reasons: string[];
  onlyOfflineSyntheticEvidenceAllowed: true;
  externalProviderAuthorized: false;
  googleReadTokenAvailable: false;
  googleWriteAccessAllowed: false;
  realAdministratorConsentVerified: false;
  expiresAt: string | null;
};
export const DEFAULT_LAB_POLICY: GoogleLabPolicy = {
  maxChallengeAgeSeconds: 900,
  maxConnectionAgeDays: 30,
  maxEvents: 2000,
  maxChallengeAttempts: 1,
  requireIndependentReviewerForLive: true,
  allowRealGoogleOauth: false,
  allowExternalGoogleProvider: false,
  allowAccountWrites: false,
  customerConsentNotAttested: true,
};
const stateEdges: Record<GoogleLabCommandType, GoogleLabState[]> = {
  ISSUE_CHALLENGE: ["NOT_CONFIGURED", "CONSENT_DENIED", "EXPIRED",
    "REVOKED"],
  DENY_CONSENT: ["CHALLENGE_ISSUED"],
  ACCEPT_LAB: ["CHALLENGE_ISSUED"],
  SUSPEND: ["CONNECTED_LAB"],
  RESUME: ["SUSPENDED"],
  REVOKE: ["CHALLENGE_ISSUED", "CONSENT_DENIED",
    "CONNECTED_LAB", "SUSPENDED", "EXPIRED"],
  EXPIRE: ["CHALLENGE_ISSUED", "CONNECTED_LAB", "SUSPENDED"],
  ROTATE_CHALLENGE: ["CHALLENGE_ISSUED"],
  CHANGE_CAPABILITIES: ["CONNECTED_LAB", "SUSPENDED"],
};
const nextStates: Record<GoogleLabCommandType, GoogleLabState> = {
  ISSUE_CHALLENGE: "CHALLENGE_ISSUED",
  DENY_CONSENT: "CONSENT_DENIED",
  ACCEPT_LAB: "CONNECTED_LAB",
  SUSPEND: "SUSPENDED",
  RESUME: "CONNECTED_LAB",
  REVOKE: "REVOKED",
  EXPIRE: "EXPIRED",
  ROTATE_CHALLENGE: "CHALLENGE_ISSUED",
  CHANGE_CAPABILITIES: "CONNECTED_LAB",
};
export class GoogleLabError extends Error {
  constructor(
    public readonly code:
      "INVALID" | "FORBIDDEN" | "CONFLICT" | "EXPIRED" | "MISSING",
    message: string,
  ) { super(message); this.name = "GoogleLabError"; }
}
function reject(
  code: GoogleLabError["code"], reason: string,
): never { throw new GoogleLabError(code, reason); }
function hash(x: unknown) {
  return createHash("sha256").update(JSON.stringify(x)).digest("hex");
}
function same(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function short(x: unknown, label: string, limit = 150) {
  if (typeof x !== "string" || !x.trim() ||
      x.length > limit || /[\u0000-\u001f\u007f]/.test(x))
    reject("INVALID", "Invalid Google lab " + label + ".");
  return x.trim();
}
function clock(x: unknown, label: string) {
  if (typeof x !== "string" ||
      !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(x) ||
      !Number.isFinite(Date.parse(x)))
    reject("INVALID", "Invalid UTC " + label + ".");
  return new Date(x).toISOString();
}
function caps(value: unknown, allowEmpty = false) {
  if (!Array.isArray(value) ||
      value.length > CAPABILITIES.length ||
      (!allowEmpty && value.length < 1))
    reject("INVALID", "Capabilities must be a bounded array.");
  if (value.some(x => !CAPABILITIES.includes(x)) ||
      new Set(value).size !== value.length)
    reject("INVALID", "Invalid or repeated Google capability.");
  return [...value].sort() as GoogleCapability[];
}
export function parseGoogleLabPolicy(raw: unknown = {}) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    reject("INVALID", "Invalid LAB policy.");
  const x = raw as Record<string, unknown>;
  const allowed = Object.keys(DEFAULT_LAB_POLICY);
  if (Object.keys(x).some(key => !allowed.includes(key)))
    reject("INVALID", "Unexpected LAB policy option.");
  const values: GoogleLabPolicy = {
    ...DEFAULT_LAB_POLICY,
    ...x,
  } as GoogleLabPolicy;
  for (const [key, min, max] of [
    ["maxChallengeAgeSeconds", 60, 3600],
    ["maxConnectionAgeDays", 1, 90],
    ["maxEvents", 1, 10000],
    ["maxChallengeAttempts", 1, 5],
  ] as const) {
    const number = values[key];
    if (!Number.isSafeInteger(number) || number < min || number > max)
      reject("INVALID", "Unsupported LAB policy limit " + key + ".");
  }
  if (values.allowRealGoogleOauth !== false ||
      values.allowExternalGoogleProvider !== false ||
      values.allowAccountWrites !== false ||
      values.customerConsentNotAttested !== true ||
      values.requireIndependentReviewerForLive !== true)
    reject("FORBIDDEN", "LAB policy cannot grant production permissions.");
  return values;
}
export function validateGoogleLabScope(scope: GoogleLabScope,
  organizationId: string, manager = false) {
  short(scope?.organizationId, "organization identifier", 128);
  short(scope?.actorUserId, "actor ID", 128);
  if (scope.organizationId !== organizationId)
    reject("MISSING", "No Google LAB connection in this organization.");
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role))
    reject("FORBIDDEN", "Unknown organization role.");
  if (manager && !["OWNER", "ADMIN"].includes(scope.role))
    reject("FORBIDDEN", "Only organization administrators may configure LAB.");
}
function digestConnection(c: Omit<GoogleLabConnection, "stateDigest">) {
  return hash(c);
}
export function verifyGoogleLabConnection(connection: GoogleLabConnection) {
  const issues: string[] = [];
  const { stateDigest, ...canonical } = connection;
  if (!same(stateDigest, digestConnection(canonical)))
    issues.push("Connection content or revision was altered.");
  if (connection.provider !== "GOOGLE_WORKSPACE" ||
      connection.consentScope !== "OFFLINE_LAB_SIMULATION" ||
      connection.credentialStored ||
      connection.liveProviderConnected ||
      connection.administratorConsentVerified ||
      connection.accountMutationEnabled ||
      connection.customerDeploymentApproved)
    issues.push("LAB connection falsely claims LIVE or consent.");
  if (!Number.isSafeInteger(connection.revision) ||
      connection.revision < 0)
    issues.push("Invalid connection revision.");
  if (!CAPABILITIES.every(capability =>
    connection.permittedCapabilities.every(x => CAPABILITIES.includes(x))))
    issues.push("Unrecognized permissions.");
  if (connection.state === "CHALLENGE_ISSUED" &&
      !connection.challenge)
    issues.push("Missing active challenge.");
  if (connection.state === "REVOKED" &&
      connection.permittedCapabilities.length > 0)
    issues.push("Revoked connection retained permissions.");
  return { valid: issues.length === 0, issues };
}
export function newGoogleLabConnection(
  scope: GoogleLabScope, id: string, at: string,
): GoogleLabConnection {
  validateGoogleLabScope(scope, scope.organizationId, true);
  const timestamp = clock(at, "creation time");
  const canonical = {
    schema: "cyberpilot.google.lab.connection.v1" as const,
    id: short(id, "connection ID", 128),
    organizationId: scope.organizationId,
    createdByUserId: scope.actorUserId,
    revision: 0, state: "NOT_CONFIGURED" as const,
    createdAt: timestamp, updatedAt: timestamp,
    expiresAt: null, challenge: null,
    permittedCapabilities: [] as GoogleCapability[],
    consentScope: "OFFLINE_LAB_SIMULATION" as const,
    provider: "GOOGLE_WORKSPACE" as const,
    credentialStored: false as const,
    liveProviderConnected: false as const,
    administratorConsentVerified: false as const,
    accountMutationEnabled: false as const,
    customerDeploymentApproved: false as const,
  };
  return { ...canonical, stateDigest: digestConnection(canonical) };
}
export function digestChallengeNonce(
  organizationId: string, connectionId: string,
  nonce: string,
) {
  short(organizationId, "organization ID", 128);
  short(connectionId, "connection ID", 128);
  const raw = short(nonce, "challenge nonce", 256);
  if (!/^[a-zA-Z0-9_-]{32,256}$/.test(raw))
    reject("INVALID", "Challenge nonce requires at least 32 safe characters.");
  return createHash("sha256").update("CYBERPILOT-GOOGLE-LAB\0")
    .update(organizationId).update("\0").update(connectionId)
    .update("\0").update(raw).digest("hex");
}
export function verifyGoogleLabEvents(
  connection: GoogleLabConnection,
  events: GoogleLabEvent[],
) {
  const issues: string[] = [];
  if (events.length !== connection.revision)
    issues.push("Number of events does not equal persisted revision.");
  let prior: string | null = null;
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    const { digest, ...payload } = event;
    if (!same(digest, hash(payload)) ||
        !sameOrNull(event.previousEventDigest, prior))
      issues.push("Audit chain digest mismatch at revision " + (i + 1));
    if (event.organizationId !== connection.organizationId ||
        event.connectionId !== connection.id ||
        event.revision !== i + 1)
      issues.push("Audit chain crosses scope or skips revision.");
    if (event.realProviderContacted || event.privilegedActionPerformed)
      issues.push("LAB event claims prohibited provider action.");
    prior = event.digest;
  }
  if (events.length > 0 &&
      !same(events[events.length - 1]?.connectionDigest,
        connection.stateDigest))
    issues.push("Audit head does not match connection.");
  return { valid: issues.length === 0, issues,
    lastDigest: prior, auditedRevision: events.length };
}
function sameOrNull(a: string | null, b: string | null) {
  return a === null && b === null || same(a, b);
}
function commandShape(command: GoogleLabCommand) {
  if (!command || typeof command !== "object")
    reject("INVALID", "LAB command must be an object.");
  if (!Object.prototype.hasOwnProperty.call(stateEdges, command.type))
    reject("INVALID", "Unknown LAB command.");
  if (!Number.isSafeInteger(command.expectedRevision) ||
      command.expectedRevision < 0)
    reject("INVALID", "LAB revision must be a nonnegative integer.");
  short(command.connectionId, "command connection ID", 128);
  const date = clock(command.at, "command time");
  const reason = short(command.reason, "reason", 500);
  if (command.allowRealGoogle !== undefined &&
      command.allowRealGoogle !== false)
    reject("FORBIDDEN", "Real Google access cannot be granted in LAB.");
  return { date, reason };
}
export function transitionGoogleLab(
  connection: GoogleLabConnection,
  scope: GoogleLabScope,
  command: GoogleLabCommand,
  previousEvent: GoogleLabEvent | null = null,
  rawPolicy: unknown = {},
): GoogleLabTransition {
  const policy = parseGoogleLabPolicy(rawPolicy);
  validateGoogleLabScope(scope, connection.organizationId, true);
  if (!verifyGoogleLabConnection(connection).valid)
    reject("CONFLICT", "Cannot mutate a corrupted LAB connection.");
  const input = commandShape(command);
  if (command.connectionId !== connection.id)
    reject("MISSING", "LAB command targets a different connection.");
  if (command.expectedRevision !== connection.revision)
    reject("CONFLICT", "LAB connection revision changed.");
  if (connection.revision >= policy.maxEvents)
    reject("CONFLICT", "LAB audit history exceeds configured bound.");
  if (!stateEdges[command.type].includes(connection.state))
    reject("CONFLICT", "LAB state transition is not allowed.");
  if (input.date < connection.updatedAt)
    reject("CONFLICT", "Cannot insert out-of-order LAB event.");
  if (connection.revision > 0) {
    if (!previousEvent ||
        previousEvent.revision !== connection.revision ||
        previousEvent.connectionDigest !== connection.stateDigest ||
        command.previousEventDigest !== previousEvent.digest)
      reject("CONFLICT", "LAB CAS audit head does not match.");
  } else if (previousEvent || command.previousEventDigest)
    reject("CONFLICT", "Unexpected prior event on initial revision.");

  const next = { ...connection, revision: connection.revision + 1,
    updatedAt: input.date, permittedCapabilities:
      [...connection.permittedCapabilities],
    challenge: connection.challenge ? { ...connection.challenge,
      capabilitySet: [...connection.challenge.capabilitySet] } : null };
  const warnings = [
    "This is LAB-only simulation; no Google admin consent is attested.",
  ];
  let state = nextStates[command.type];
  switch (command.type) {
    case "ISSUE_CHALLENGE":
    case "ROTATE_CHALLENGE": {
      const nonce = command.challengeNonce;
      if (typeof nonce !== "string")
        reject("INVALID", "LAB challenge nonce is required.");
      const requested = caps(command.requestedCapabilities);
      const expiresAt = new Date(Date.parse(input.date) +
        policy.maxChallengeAgeSeconds * 1000).toISOString();
      next.challenge = {
        challengeDigest: digestChallengeNonce(connection.organizationId,
          connection.id, nonce),
        organizationId: connection.organizationId,
        requestedByUserId: scope.actorUserId,
        requestedAt: input.date, expiresAt,
        requestDigest: hash({ organizationId: connection.organizationId,
          connectionId: connection.id, requested }),
        usedAt: null, revokedAt: null, attempts: 0,
        capabilitySet: requested,
        providerOrigin: "SYNTHETIC_FIXTURE",
        realGoogleOauthPerformed: false,
      };
      next.expiresAt = null;
      next.permittedCapabilities = [];
      break;
    }
    case "ACCEPT_LAB": {
      if (!next.challenge)
        reject("CONFLICT", "LAB acceptance missing challenge.");
      const nonce = command.challengeNonce;
      if (typeof nonce !== "string")
        reject("INVALID", "LAB acceptance requires nonce.");
      if (input.date >= next.challenge.expiresAt)
        reject("EXPIRED", "LAB challenge already expired.");
      if (next.challenge.usedAt || next.challenge.revokedAt ||
          next.challenge.attempts >= policy.maxChallengeAttempts)
        reject("CONFLICT", "LAB challenge already consumed.");
      const candidate = digestChallengeNonce(
        connection.organizationId, connection.id, nonce);
      if (!same(candidate, next.challenge.challengeDigest))
        reject("FORBIDDEN", "LAB challenge does not match.");
      next.challenge.attempts++;
      next.challenge.usedAt = input.date;
      next.permittedCapabilities = [...next.challenge.capabilitySet];
      next.expiresAt = new Date(Date.parse(input.date) +
        policy.maxConnectionAgeDays * 86400000).toISOString();
      warnings.push("Lab acceptance does not authorize an external API.");
      break;
    }
    case "DENY_CONSENT":
      if (next.challenge) next.challenge.revokedAt = input.date;
      next.permittedCapabilities = [];
      next.expiresAt = null;
      break;
    case "SUSPEND":
      next.permittedCapabilities = [];
      warnings.push("A suspended connection cannot read even LAB data.");
      break;
    case "RESUME":
      if (!connection.expiresAt || input.date >= connection.expiresAt)
        reject("EXPIRED", "Cannot resume an expired LAB connection.");
      if (!connection.challenge?.usedAt)
        reject("CONFLICT", "Resumption requires previously completed LAB challenge.");
      next.permittedCapabilities =
        [...connection.challenge.capabilitySet];
      break;
    case "REVOKE":
      next.permittedCapabilities = [];
      next.expiresAt = null;
      if (next.challenge) next.challenge.revokedAt = input.date;
      break;
    case "EXPIRE":
      if (connection.state === "CHALLENGE_ISSUED") {
        if (!connection.challenge ||
            input.date < connection.challenge.expiresAt)
          reject("CONFLICT", "Challenge has not expired yet.");
      } else if (!connection.expiresAt ||
        input.date < connection.expiresAt)
        reject("CONFLICT", "Connection has not expired yet.");
      next.permittedCapabilities = [];
      next.expiresAt = null;
      if (next.challenge) next.challenge.revokedAt = input.date;
      break;
    case "CHANGE_CAPABILITIES": {
      const requested = caps(command.requestedCapabilities);
      const initial = connection.challenge?.capabilitySet ?? [];
      if (requested.some(c => !initial.includes(c)))
        reject("FORBIDDEN", "Cannot escalate LAB capability without new challenge.");
      if (connection.state === "SUSPENDED") {
        next.permittedCapabilities = [];
        if (next.challenge)
          next.challenge.capabilitySet = requested;
        state = "SUSPENDED";
      } else next.permittedCapabilities = requested;
      break;
    }
    default:
      reject("INVALID", "Unsupported Google LAB mutation.");
  }
  next.state = state;
  const canonical = {
    schema: next.schema, id: next.id,
    organizationId: next.organizationId,
    createdByUserId: next.createdByUserId,
    revision: next.revision, state: next.state,
    createdAt: next.createdAt, updatedAt: next.updatedAt,
    expiresAt: next.expiresAt, challenge: next.challenge,
    permittedCapabilities: next.permittedCapabilities,
    consentScope: next.consentScope, provider: next.provider,
    credentialStored: false as const,
    liveProviderConnected: false as const,
    administratorConsentVerified: false as const,
    accountMutationEnabled: false as const,
    customerDeploymentApproved: false as const,
  };
  const updated: GoogleLabConnection = {
    ...canonical, stateDigest: digestConnection(canonical),
  };
  const eventCanonical = {
    schema: "cyberpilot.google.lab.event.v1" as const,
    organizationId: connection.organizationId,
    connectionId: connection.id, revision: updated.revision,
    type: command.type, actorUserId: scope.actorUserId,
    at: input.date, from: connection.state, to: state,
    previousEventDigest: previousEvent?.digest ?? null,
    connectionDigest: updated.stateDigest,
    challengeDigest: updated.challenge?.challengeDigest ?? null,
    requestedCapabilityCount: updated.permittedCapabilities.length,
    explanationCode: command.type,
    realProviderContacted: false as const,
    privilegedActionPerformed: false as const,
  };
  return {
    connection: updated,
    event: { ...eventCanonical, digest: hash(eventCanonical) },
    warnings,
    sideEffects: {
      googleApiRequests: 0, oauthTokensGranted: 0,
      accountWrites: 0, customerConsentRecordedAsReal: false,
      requiresDatabaseTransaction: true,
    },
  };
}
export function inspectGoogleLabEligibility(
  connection: GoogleLabConnection, scope: GoogleLabScope,
  now: string, requested: GoogleCapability[] = [...CAPABILITIES],
): GoogleLabAcceptance {
  validateGoogleLabScope(scope, connection.organizationId);
  if (!verifyGoogleLabConnection(connection).valid)
    reject("CONFLICT", "Cannot inspect corrupted LAB evidence.");
  const at = clock(now, "eligibility clock");
  const requestedCaps = caps(requested, true);
  const expired = connection.expiresAt !== null &&
    at >= connection.expiresAt;
  const active = connection.state === "CONNECTED_LAB" && !expired;
  const allowed = active ? requestedCaps.filter(c =>
    connection.permittedCapabilities.includes(c)) : [];
  const blocked = requestedCaps.filter(c => !allowed.includes(c));
  const reasons: string[] = [];
  if (!active)
    reasons.push(expired ? "LAB_CONNECTION_EXPIRED" :
      "LAB_CONNECTION_NOT_ACTIVE");
  if (blocked.length)
    reasons.push("CAPABILITY_NOT_GRANTED_FOR_LAB");
  if (scope.role === "AUDITOR")
    reasons.push("AUDITOR_IS_READ_ONLY");
  reasons.push("NO_REAL_GOOGLE_PROVIDER_CONSENT");
  return {
    eligible: active && blocked.length === 0,
    connectionId: connection.id,
    organizationId: connection.organizationId,
    revision: connection.revision,
    effectiveState: expired ? "EXPIRED" : connection.state,
    allowedCapabilities: allowed, blockedCapabilities: blocked,
    reasons, onlyOfflineSyntheticEvidenceAllowed: true,
    externalProviderAuthorized: false,
    googleReadTokenAvailable: false,
    googleWriteAccessAllowed: false,
    realAdministratorConsentVerified: false,
    expiresAt: connection.expiresAt,
  };
}
export function replayGoogleLabHistory(
  initial: GoogleLabConnection,
  events: GoogleLabEvent[],
) {
  if (initial.revision !== 0)
    reject("INVALID", "History must begin at initial revision.");
  if (events.length > 10000)
    reject("INVALID", "LAB history exceeds bounded replay.");
  const chronology = events.map(e => ({
    revision: e.revision, type: e.type, state: e.to,
    actorUserId: e.actorUserId,
    eventDigest: e.digest, connectionDigest: e.connectionDigest,
  }));
  const issues: string[] = [];
  for (let i = 0; i < events.length; i++) {
    const event = events[i]!;
    if (event.revision !== i + 1)
      issues.push("REVISION_GAP_" + (i + 1));
    if (i === 0 && event.previousEventDigest !== null)
      issues.push("FIRST_EVENT_HAS_PARENT");
    if (i > 0 && !same(events[i - 1]!.digest,
      event.previousEventDigest))
      issues.push("CHAIN_LINK_MISMATCH_" + event.revision);
    const { digest, ...payload } = event;
    if (!same(hash(payload), digest))
      issues.push("TAMPERED_EVENT_" + event.revision);
    if (event.organizationId !== initial.organizationId ||
        event.connectionId !== initial.id)
      issues.push("TENANT_SCOPE_MISMATCH");
    if (event.realProviderContacted ||
        event.privilegedActionPerformed)
      issues.push("FORBIDDEN_LIVE_CLAIM");
    if (i > 0 && events[i - 1]!.at > event.at)
      issues.push("TIME_REORDERED");
  }
  return {
    valid: issues.length === 0,
    issues, chronology,
    eventCount: events.length,
    finalRevision: events.length,
    finalState: events.at(-1)?.to ?? initial.state,
    finalDigest: events.at(-1)?.connectionDigest ??
      initial.stateDigest,
    realGoogleConsentAttested: false as const,
    providerApiCalls: 0 as const,
  };
}
export function redactGoogleLabConnection(connection: GoogleLabConnection) {
  if (!verifyGoogleLabConnection(connection).valid)
    reject("CONFLICT", "Invalid LAB state.");
  return {
    schema: connection.schema, id: connection.id,
    organizationId: connection.organizationId,
    revision: connection.revision, state: connection.state,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
    expiresAt: connection.expiresAt,
    permittedCapabilities: [...connection.permittedCapabilities],
    challenge: connection.challenge ? {
      expiresAt: connection.challenge.expiresAt,
      used: !!connection.challenge.usedAt,
      revoked: !!connection.challenge.revokedAt,
      capabilityCount: connection.challenge.capabilitySet.length,
    } : null,
    stateDigest: connection.stateDigest,
    realProviderConnected: false as const,
    administratorConsentVerified: false as const,
    oauthTokensPresent: false as const,
  };
}
