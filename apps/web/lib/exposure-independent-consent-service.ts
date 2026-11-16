import { db } from "@cyberpilot/database";
import {
  validateIndependentConsent,
  verifyIndependentConsentReport,
  exportIndependentConsentReport,
  type ConsentGrant,
  type DetachedConsentEnvelope,
  type IndependentConsentVerification,
  type TrustedConsentKey,
  type ConsentRevocationStatus,
} from "./exposure-independent-consent";

/**
 * Operator-managed consent verification service. Browser requests NEVER
 * supply independent authority keys, remote withdrawal state, consent
 * records or executable leases. Authentication and owner permissions
 * are rechecked against the current database membership on every call.
 */
export type ConsentReviewActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type ConsentReviewCommand = {
  operation: "ANALYZE" | "READ_AUTHORIZATION" |
    "GET_CONSENT_REQUIREMENTS" | "EXPORT_CHECK";
  domain: string;
  envelope?: DetachedConsentEnvelope;
  authorizationRevision?: number;
  sources?: Array<"DNS" | "TLS_HANDSHAKE" | "HTTPS_HEADERS">;
  format?: "JSON" | "CSV" | "MARKDOWN";
};
export type ConsentAuthorityAdapter = {
  trustedKeys(
    organizationId: string, at: string,
  ): Promise<TrustedConsentKey[]>;
  /**
   * Fresh status MUST come from an authenticated independent endpoint.
   * The service does not ship a default adapter or unsigned fallback.
   */
  readWithdrawal(
    grant: ConsentGrant, at: string,
  ): Promise<ConsentRevocationStatus | null>;
  independentlyOperated: true;
};
export type ConsentReviewResult = {
  schema: "cyberpilot.exposure.consent.review.service.v1";
  organizationId: string;
  operation: ConsentReviewCommand["operation"];
  data: unknown;
  networkCollectionStarted: false;
  legalCustomerApprovalSignedByCyberPilot: false;
  scoreMutated: false;
  executableLeaseIssued: false;
};
export class ConsentReviewError extends Error {
  constructor(message: string) { super("Consent review: " + message); }
}
const validSources = [
  "DNS","TLS_HANDSHAKE","HTTPS_HEADERS",
] as const;
function fail(reason: string): never {
  throw new ConsentReviewError(reason);
}
function safeId(x: unknown): x is string {
  return typeof x === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
}
function canonicalDomain(x: unknown): x is string {
  return typeof x === "string" &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(x) &&
    x.length >= 4 && x.length <= 253 &&
    x.includes(".") && !x.includes("..") &&
    !x.endsWith(".local");
}
function parseCommand(raw: unknown): ConsentReviewCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected a JSON command.");
  const fields = raw as Record<string, unknown>;
  const keys = [
    "operation", "domain", "envelope",
    "authorizationRevision", "sources", "format",
  ];
  if (Object.keys(fields).some(k => !keys.includes(k)))
    fail("Unexpected field; keys and revocations must be server-managed.");
  if (!["ANALYZE","READ_AUTHORIZATION",
        "GET_CONSENT_REQUIREMENTS","EXPORT_CHECK"].includes(
          fields.operation as string))
    fail("Unsupported consent command.");
  if (!canonicalDomain(fields.domain))
    fail("Domain must be canonical and public.");
  if (fields.sources !== undefined) {
    if (!Array.isArray(fields.sources) ||
        fields.sources.length < 1 || fields.sources.length > 3 ||
        new Set(fields.sources).size !== fields.sources.length ||
        fields.sources.some(s => !validSources.includes(s)))
      fail("Source list invalid.");
  }
  if (fields.authorizationRevision !== undefined &&
      (!Number.isSafeInteger(fields.authorizationRevision) ||
       (fields.authorizationRevision as number) < 1))
    fail("Authorization revision invalid.");
  if (fields.envelope !== undefined) {
    if (typeof fields.envelope !== "object" ||
        fields.envelope === null || Array.isArray(fields.envelope))
      fail("Detached envelope must be an object.");
    if (JSON.stringify(fields.envelope).length > 20000)
      fail("Consent envelope exceeds safe size.");
  }
  if (fields.format !== undefined &&
      !["JSON","CSV","MARKDOWN"].includes(fields.format as string))
    fail("Unsupported export format.");
  const operation = fields.operation as ConsentReviewCommand["operation"];
  if (["ANALYZE","EXPORT_CHECK"].includes(operation) &&
      (!fields.sources || !fields.authorizationRevision))
    fail("Current revision and requested sources are mandatory.");
  return {
    operation,
    domain: fields.domain,
    envelope: fields.envelope as DetachedConsentEnvelope | undefined,
    sources: fields.sources as ConsentReviewCommand["sources"],
    authorizationRevision:
      fields.authorizationRevision as number | undefined,
    format: fields.format as ConsentReviewCommand["format"],
  };
}
function noExternalAuthority(): ConsentAuthorityAdapter {
  return {
    independentlyOperated: true,
    trustedKeys: async () => [],
    readWithdrawal: async () => null,
  };
}
export const unavailableIndependentConsentAuthority =
  noExternalAuthority();
async function member(actor: ConsentReviewActor) {
  if (!safeId(actor.userId) || !safeId(actor.organizationId))
    fail("Actor identity invalid.");
  if (!["OWNER","ADMIN","MEMBER","AUDITOR"].includes(actor.role))
    fail("Unknown actor role.");
  const membership = await db.membership.findFirst({
    where: { organizationId: actor.organizationId,
      userId: actor.userId },
    select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("Active organization membership required.");
  return membership.role;
}
function requirementOverview(
  organizationId: string, domain: string,
) {
  return {
    schema: "cyberpilot.exposure.consent.requirements.v1",
    organizationId, domain,
    proofOfDomainOwnershipInsufficientForLegalConsent: true,
    domainClaimMustBeCurrent: true,
    detachedAuthoritySignature: "Ed25519",
    independentTrustKeyRequired: true,
    authenticatedWithdrawalRefreshRequired: true,
    maximumWithdrawalStalenessMs: 60000,
    maximumScopeGrantDurationMs: 604800000,
    sourceNetworkAccessByThisService: false,
    requiredSignedCapabilities: {
      allowActiveScanning: false,
      allowAuthentication: false,
      allowRedirects: false,
      requirePinnedPeer: true,
    },
    requiredOperationalGates: [
      "Tenant and verified domain identity",
      "Independent legal authority signature and operator trust store",
      "Recent authenticated grant withdrawal status",
      "Executable single-tenant PostgreSQL reservation",
      "Fresh authorization revision and source-limited lease",
      "Network-isolated worker enforcing public pinned peers",
      "Per-operation durable quotas and terminal audit",
    ],
    currentLegalConsentAutomaticallyEstablished: false,
    availableLIVECollectors: 0,
  };
}
export class ExposureIndependentConsentService {
  constructor(
    private readonly authority: ConsentAuthorityAdapter =
      unavailableIndependentConsentAuthority,
  ) {}
  async execute(actor: ConsentReviewActor,
    raw: unknown): Promise<ConsentReviewResult> {
    const command = parseCommand(raw);
    await member(actor);
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.exposure.consent.review.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation,
      data,
      networkCollectionStarted: false,
      legalCustomerApprovalSignedByCyberPilot: false,
      scoreMutated: false,
      executableLeaseIssued: false,
    };
  }
  private async dispatch(
    actor: ConsentReviewActor, command: ConsentReviewCommand,
  ): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (command.operation === "GET_CONSENT_REQUIREMENTS")
      return requirementOverview(organizationId, command.domain);
    const authorization = await db.exposureDomainAuthorization.findFirst({
      where: { organizationId, domain: command.domain },
    });
    if (!authorization)
      fail("Domain authorization missing in this organization.");
    if (command.operation === "READ_AUTHORIZATION")
      return {
        organizationId, domain: authorization.domain,
        authorizationId: authorization.id,
        revision: authorization.revision,
        state: authorization.state,
        method: authorization.method,
        verifiedAt: authorization.verifiedAt?.toISOString() ?? null,
        revokedAt: authorization.revokedAt?.toISOString() ?? null,
        expiresAt: authorization.challengeExpiresAt.toISOString(),
        legalConsentIndependentlyVerified: false,
        LIVECollectionEnabled: false,
      };
    if (command.authorizationRevision !== authorization.revision)
      fail("Consent analysis must bind current authorization revision.");
    const now = new Date().toISOString();
    const requested = command.sources ?? [];
    let trustedKeys: TrustedConsentKey[] = [];
    let withdrawal: ConsentRevocationStatus | null = null;
    if (this.authority.independentlyOperated) {
      try {
        trustedKeys = await this.authority.trustedKeys(
          organizationId, now,
        );
      } catch { trustedKeys = []; }
      if (command.envelope?.grant) {
        try {
          withdrawal = await this.authority.readWithdrawal(
            command.envelope.grant, now,
          );
        } catch { withdrawal = null; }
      }
    }
    const report = validateIndependentConsent(
      command.envelope ?? null,
      {
        organizationId,
        domain: command.domain,
        authorizationId: authorization.id,
        authorizationRevision: authorization.revision,
        actorUserId: actor.userId,
        requestedSources: requested,
        requestedAt: now,
        trustedKeys,
        withdrawal,
      },
    );
    if (!verifyIndependentConsentReport(report, organizationId).valid)
      fail("Detached consent report did not pass integrity check.");
    const proofCurrent = authorization.state === "VERIFIED" &&
      authorization.verifiedAt !== null &&
      authorization.revokedAt === null &&
      authorization.challengeExpiresAt > new Date();
    // A signed independent grant cannot override stale proof. The
    // context provided by a browser never issues a legal authorization.
    const admitted = false as const;
    const result = {
      report,
      currentTechnicalOwnershipProof: proofCurrent,
      independentAuthorityConnected:
        this.authority !== unavailableIndependentConsentAuthority,
      operationalAdmissionGranted: admitted,
      networkWorkerAvailable: false as const,
      independentlySignedConsentCreatedHere: false as const,
      executableQuotaReservationCreated: false as const,
      reasonForNoNetwork:
        !proofCurrent ? "DOMAIN_PROOF_NOT_CURRENT" :
        report.decision === "DENIED" ?
          "INDEPENDENT_GRANT_UNVERIFIED" :
          "EXECUTABLE_LEASE_AND_TRUSTED_WORKER_MISSING",
    };
    if (command.operation !== "EXPORT_CHECK") return result;
    const artifact = exportIndependentConsentReport(
      report, command.format ?? "JSON",
    );
    return {
      ...result,
      artifact,
      containsOriginalSignature: false,
      containsCustomerCredentials: false,
      externallySignedCustomerApprovalGenerated: false,
    };
  }
}
