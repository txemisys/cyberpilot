import { db } from "@cyberpilot/database";
import {
  checkPassiveAdmission, defaultPassiveAdmissionPolicy,
  planPassiveDomainTargets, verifyPassiveLedger, sha256V2,
  type PassiveCollectorRequest, type PassiveSource,
  type PassiveAdmissionPolicy, type PassiveCollectionLedger,
} from "@cyberpilot/risk-engine";

/**
 * Admission is deliberately separate from the executor. A valid
 * DNS challenge proves limited domain control, not legal consent
 * for arbitrary scanning. No network request occurs here.
 */
export type PassiveActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type PassiveAdmitCommand = {
  operation: "ADMIT" | "READ_AUTHORIZATION" |
    "CHECK_SCOPE" | "DRY_RUN" | "VERIFY_LEDGER";
  domain?: string;
  requestId?: string;
  sources?: PassiveSource[];
  explicitlyOptedIn?: boolean;
  consentRecordId?: string;
  trustedLegalConsentVerified?: false;
  expectedAuthorizationRevision?: number;
  evaluatedAt?: string;
  ledger?: PassiveCollectionLedger;
};
export type PassiveAdmitResponse = {
  schema: "cyberpilot.exposure.passive.service.v1";
  organizationId: string;
  operation: PassiveAdmitCommand["operation"];
  data: unknown;
  noNetworkRequests: true;
  cannotScanWithoutExternalConsent: true;
  credentialsStored: false;
  legacyCyberScoreModified: false;
  customerCertifiedSecure: false;
};
type StoredAuthorization = {
  id: string; organizationId: string; domain: string;
  revision: number; state: string; method: string;
  challengeExpiresAt: Date;
  verifiedAt: Date | null; revokedAt: Date | null;
  actorUserId: string; createdAt: Date;
};
function invalid(reason: string): never {
  throw Error("Exposure admission: " + reason);
}
function safeId(value: unknown): value is string {
  return typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function time(x: unknown): x is string {
  return typeof x === "string" &&
    /^\d{4}-\d\d-\d\dT/.test(x) &&
    Number.isFinite(Date.parse(x)) &&
    new Date(x).toISOString() === x;
}
function parse(raw: unknown): PassiveAdmitCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    invalid("Expected request object.");
  const data = raw as Record<string, unknown>;
  const fields = [
    "operation", "domain", "requestId", "sources",
    "explicitlyOptedIn", "consentRecordId",
    "trustedLegalConsentVerified", "expectedAuthorizationRevision",
    "evaluatedAt", "ledger",
  ];
  if (Object.keys(data).some(x => !fields.includes(x)))
    invalid("Unexpected request field.");
  const operations: PassiveAdmitCommand["operation"][] = [
    "ADMIT","READ_AUTHORIZATION","CHECK_SCOPE","DRY_RUN",
    "VERIFY_LEDGER",
  ];
  if (!operations.includes(data.operation as PassiveAdmitCommand["operation"]))
    invalid("Unknown admission operation.");
  const command: PassiveAdmitCommand = {
    operation: data.operation as PassiveAdmitCommand["operation"],
  };
  if (data.domain !== undefined) {
    if (typeof data.domain !== "string")
      invalid("Domain must be a string.");
    command.domain = data.domain;
  }
  if (data.requestId !== undefined) {
    if (!safeId(data.requestId))
      invalid("Invalid collection request ID.");
    command.requestId = data.requestId;
  }
  if (data.sources !== undefined) {
    if (!Array.isArray(data.sources) ||
        data.sources.length > 3 ||
        data.sources.some(x => ![
          "DNS", "HTTPS_HEADERS", "TLS_HANDSHAKE"].includes(String(x))))
      invalid("Unknown passive source.");
    command.sources = data.sources as PassiveSource[];
  }
  if (data.explicitlyOptedIn !== undefined) {
    if (typeof data.explicitlyOptedIn !== "boolean")
      invalid("Opt in must be boolean.");
    command.explicitlyOptedIn = data.explicitlyOptedIn;
  }
  if (data.consentRecordId !== undefined) {
    if (!safeId(data.consentRecordId))
      invalid("Invalid consent reference.");
    command.consentRecordId = data.consentRecordId;
  }
  if (data.trustedLegalConsentVerified !== undefined) {
    // The browser must never be able to mark legal consent verified.
    if (data.trustedLegalConsentVerified !== false)
      invalid("User assertion cannot establish legal consent.");
    command.trustedLegalConsentVerified = false;
  }
  if (data.expectedAuthorizationRevision !== undefined) {
    if (!Number.isSafeInteger(data.expectedAuthorizationRevision) ||
        (data.expectedAuthorizationRevision as number) < 1 ||
        (data.expectedAuthorizationRevision as number) > 1e7)
      invalid("Invalid authorization version.");
    command.expectedAuthorizationRevision =
      data.expectedAuthorizationRevision as number;
  }
  if (data.evaluatedAt !== undefined) {
    if (!time(data.evaluatedAt))
      invalid("Invalid evaluation clock.");
    command.evaluatedAt = data.evaluatedAt;
  }
  if (data.ledger !== undefined) {
    if (!data.ledger || typeof data.ledger !== "object" ||
        Array.isArray(data.ledger))
      invalid("Expected signed local ledger structure.");
    command.ledger = data.ledger as PassiveCollectionLedger;
  }
  if (command.operation !== "VERIFY_LEDGER" && !command.domain)
    invalid("Missing target domain.");
  if (command.operation === "ADMIT" &&
      (!command.requestId || !command.sources ||
       command.explicitlyOptedIn !== true))
    invalid("Admission requires explicit operator request.");
  if (command.operation === "VERIFY_LEDGER" && !command.ledger)
    invalid("Missing collection ledger.");
  return command;
}
async function scope(actor: PassiveActor) {
  if (!safeId(actor.organizationId) || !safeId(actor.userId))
    invalid("Invalid tenant or user identifier.");
  const member = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId,
      userId: actor.userId,
    }, select: { role: true },
  });
  if (!member || member.role !== actor.role)
    invalid("Current organization membership required.");
  return member.role;
}
function proofFromRow(
  row: StoredAuthorization, actor: PassiveActor,
  consentRecordId: string,
  legalConsentIndependentlyVerified: boolean,
) {
  return {
    organizationId: row.organizationId, domain: row.domain,
    authorizationId: row.id,
    authorizationRevision: row.revision,
    verificationMethod: row.method as "DNS_TOKEN" | "HTTP_TOKEN",
    verifiedAt: row.verifiedAt?.toISOString() ?? "",
    expiresAt: row.challengeExpiresAt.toISOString(),
    revokedAt: row.revokedAt?.toISOString() ?? null,
    currentState: row.state as
      "VERIFIED" | "PENDING" | "REVOKED" | "EXPIRED",
    actorUserId: actor.userId,
    consentRecordId,
    legalConsentIndependentlyVerified,
  };
}
function makeRequest(actor: PassiveActor,
  row: StoredAuthorization,
  command: PassiveAdmitCommand,
  now: string,
  policy: PassiveAdmissionPolicy,
  legalConsentIndependentlyVerified: boolean,
): PassiveCollectorRequest {
  const sources = command.sources ?? ["DNS"];
  const targets = planPassiveDomainTargets(row.domain, sources);
  return {
    schema: "cyberpilot.exposure.passive.request.v1",
    organizationId: actor.organizationId,
    domain: row.domain,
    requestId: command.requestId ?? "dryrun-" +
      sha256V2(actor.userId + now).slice(0, 20),
    actorUserId: actor.userId, requestedAt: now,
    proof: proofFromRow(row, actor,
      command.consentRecordId ?? "not-consented-0000",
      legalConsentIndependentlyVerified),
    sources, ...targets,
    policy, explicitlyOptedIn: command.explicitlyOptedIn ?? false,
    tokenInRequest: false, credentialsSupplied: false,
    activeScanningRequested: false,
  };
}
export class ExposurePassiveAdmissionService {
  async execute(actor: PassiveActor,
    raw: unknown): Promise<PassiveAdmitResponse> {
    const command = parse(raw);
    const role = await scope(actor);
    if (["ADMIT","CHECK_SCOPE"].includes(command.operation) &&
        !["OWNER","ADMIN"].includes(role))
      invalid("Only domain administrators can request collection.");
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.exposure.passive.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation, data,
      noNetworkRequests: true,
      cannotScanWithoutExternalConsent: true,
      credentialsStored: false, legacyCyberScoreModified: false,
      customerCertifiedSecure: false,
    };
  }
  private async dispatch(actor: PassiveActor,
    command: PassiveAdmitCommand): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (command.operation === "VERIFY_LEDGER") {
      const ledger = command.ledger!;
      const check = verifyPassiveLedger(ledger, organizationId);
      return {
        ...check, externalCollectorSignatureAuthenticated: false,
        acceptedAsSecurityCertificate: false,
      };
    }
    const row = await db.exposureDomainAuthorization.findFirst({
      where: { organizationId, domain: command.domain! },
    });
    if (!row)
      invalid("Domain registration not found in organization.");
    if (command.expectedAuthorizationRevision &&
        command.expectedAuthorizationRevision !== row.revision)
      invalid("Authorization revision has changed.");
    const now = command.evaluatedAt ?? new Date().toISOString();
    const expired = now > row.challengeExpiresAt.toISOString();
    const state = expired && row.state !== "REVOKED" ?
      "EXPIRED" : row.state;
    if (command.operation === "READ_AUTHORIZATION")
      return {
        authorizationId: row.id,
        domain: row.domain, revision: row.revision, state,
        authorizedAt: row.verifiedAt?.toISOString() ?? null,
        expiresAt: row.challengeExpiresAt.toISOString(),
        method: row.method,
        legalConsentConfirmedByRegistry: false,
        activeScanningAuthorized: false,
        otherOrganizationDataVisible: false,
      };
    const policy = defaultPassiveAdmissionPolicy(
      organizationId, row.domain);
    const request = makeRequest(actor, {
      ...row, state,
    }, command, now, policy, false);
    const verdict = checkPassiveAdmission(request, now);
    if (command.operation === "DRY_RUN")
      return {
        verdict, plan: {
          dnsNames: request.allowedDnsNames,
          tlsHostnames: request.allowedTlsHostnames,
          httpsHeaders: request.allowedHttpUrls,
        },
        policy,
        simulationOnly: true,
        networkRequests: 0,
      };
    if (command.operation === "CHECK_SCOPE")
      return {
        verdict,
        legalConsentEstablishedFromBrowser: false,
        requestCanBeExecuted: false,
      };
    // Fail closed even with a valid DNS ownership challenge:
    // the service has no independently authenticated legal authorization.
    return {
      verdict: {
        ...verdict, eligible: false,
        issues: [...new Set([
          ...verdict.issues, "NO_INDEPENDENT_LEGAL_CONSENT_SERVICE",
        ])],
        permittedSources: [],
      },
      admitted: false,
      activeCollectionStarted: false,
      sourceWriteOperations: 0,
      requiresAuthorizedConsentBackend: true,
      domain: row.domain,
      authorizationRevision: row.revision,
    };
  }
}
