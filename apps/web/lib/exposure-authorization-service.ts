import { randomBytes } from "node:crypto";
import { verifyExposureDnsProof,
  classifyExposureProofForPersisting,
} from "./exposure-dns-proof";
import { db, type Prisma } from "@cyberpilot/database";
import {
  normalizeExposureDomain,
  prepareExposureAuthorizationChallenge,
  type ExposureAuthorizationRequest,
  sha256V2,
} from "@cyberpilot/risk-engine";

/** Domain-ownership challenge issuance and revocation, never a scanner. */
export type ExposureAuthorizationActor = {
  organizationId: string;
  userId: string;
  role: "OWNER" | "ADMIN" | "MEMBER" | "AUDITOR";
};
export type ExposureAuthorizationOperation =
  "ISSUE" | "REPLACE" | "READ" | "LIST" |
  "REVOKE" | "EXPIRE" | "HISTORY" | "VERIFY_DNS";
export type ExposureAuthorizationCommand = {
  operation: ExposureAuthorizationOperation;
  domain?: string;
  method?: "DNS_TOKEN" | "HTTP_TOKEN";
  expectedRevision?: number;
  limit?: number;
  proofToken?: string;
};
export type ExposureAuthorizationRecord = {
  id: string;
  organizationId: string;
  domain: string;
  revision: number;
  state: "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
  method: "DNS_TOKEN" | "HTTP_TOKEN";
  challengeDigest: string;
  challengeExpiresAt: string;
  verifiedAt: string | null;
  revokedAt: string | null;
  lastCheckedAt: string | null;
  evidenceDigest: string | null;
  issuedAt: string;
  mayScanAutomatically: false;
  legalConsentProven: false;
  remoteHostProbed: false;
};
export type ExposureAuthorizationResult = {
  schema: "cyberpilot.exposure.authorization.service.v1";
  organizationId: string;
  operation: ExposureAuthorizationOperation;
  data: unknown;
  httpRequestsMade: 0;
  dnsQueriesMade: number;
  portScansMade: 0;
  signedCustomerApproval: false;
  legacyCyberScoreModified: false;
};
export class ExposureAuthorizationConflict extends Error {
  constructor() {
    super("Exposure authorization revision changed; refresh before writing.");
  }
}
function fail(message: string): never {
  throw Error("Exposure authorization: " + message);
}
function int(value: unknown, low: number, high: number) {
  if (typeof value !== "number" ||
      !Number.isSafeInteger(value) ||
      value < low || value > high)
    fail("Invalid bounded number.");
  return value;
}
function id(value: string) {
  return /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
}
function parseCommand(raw: unknown): ExposureAuthorizationCommand {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    fail("Expected command object.");
  const x = raw as Record<string, unknown>;
  if (Object.keys(x).some(k =>
      !["operation","domain","method","expectedRevision","limit",
        "proofToken"].includes(k)))
    fail("Unsupported authorization request fields.");
  const operations: ExposureAuthorizationOperation[] = [
    "ISSUE","REPLACE","READ","LIST","REVOKE","EXPIRE","HISTORY",
    "VERIFY_DNS",
  ];
  if (!operations.includes(x.operation as ExposureAuthorizationOperation))
    fail("Invalid authorization operation.");
  const command: ExposureAuthorizationCommand = {
    operation: x.operation as ExposureAuthorizationOperation,
  };
  if (x.domain !== undefined) {
    if (typeof x.domain !== "string")
      fail("Domain must be a string.");
    const canonical = normalizeExposureDomain(x.domain);
    if (x.domain !== canonical)
      fail("Domain must be canonical lowercase DNS.");
    command.domain = canonical;
  }
  if (x.method !== undefined) {
    if (!["DNS_TOKEN", "HTTP_TOKEN"].includes(String(x.method)))
      fail("Unsupported proof method.");
    command.method = x.method as "DNS_TOKEN" | "HTTP_TOKEN";
  }
  if (x.expectedRevision !== undefined)
    command.expectedRevision = int(x.expectedRevision, 0, 1000000);
  if (x.limit !== undefined)
    command.limit = int(x.limit, 1, 100);
  if (x.proofToken !== undefined) {
    if (typeof x.proofToken !== "string" ||
        !/^[a-f0-9]{64}$/.test(x.proofToken))
      fail("Proof token must be a 64-character random challenge.");
    command.proofToken = x.proofToken;
  }
  if (command.operation !== "LIST" &&
      !command.domain)
    fail("Target domain is required.");
  if (["ISSUE","REPLACE"].includes(command.operation) &&
      !command.method)
    fail("Proof method is required.");
  if (["ISSUE","REPLACE","REVOKE","EXPIRE","VERIFY_DNS"].includes(command.operation) &&
      command.expectedRevision === undefined)
    fail("Expected revision is required.");
  if (command.operation === "VERIFY_DNS" && !command.proofToken)
    fail("DNS proof token must be provided at verification time.");
  return command;
}
function view(row: {
  id: string;
  organizationId: string;
  domain: string;
  revision: number;
  state: string;
  method: string;
  challengeDigest: string;
  challengeExpiresAt: Date;
  verifiedAt: Date | null;
  revokedAt: Date | null;
  lastCheckedAt: Date | null;
  evidenceDigest: string | null;
  createdAt: Date;
}): ExposureAuthorizationRecord {
  if (!["PENDING","VERIFIED","EXPIRED","REVOKED"].includes(row.state) ||
      !["DNS_TOKEN","HTTP_TOKEN"].includes(row.method) ||
      !/^[a-f0-9]{64}$/.test(row.challengeDigest))
    fail("Stored proof state or digest invalid.");
  return {
    id: row.id, organizationId: row.organizationId,
    domain: row.domain, revision: row.revision,
    state: row.state as ExposureAuthorizationRecord["state"],
    method: row.method as ExposureAuthorizationRecord["method"],
    challengeDigest: row.challengeDigest,
    challengeExpiresAt: row.challengeExpiresAt.toISOString(),
    verifiedAt: row.verifiedAt?.toISOString() ?? null,
    revokedAt: row.revokedAt?.toISOString() ?? null,
    lastCheckedAt: row.lastCheckedAt?.toISOString() ?? null,
    evidenceDigest: row.evidenceDigest,
    issuedAt: row.createdAt.toISOString(),
    mayScanAutomatically: false,
    legalConsentProven: false,
    remoteHostProbed: false,
  };
}
async function authorize(actor: ExposureAuthorizationActor,
  mutation: boolean) {
  if (!id(actor.organizationId) || !id(actor.userId))
    fail("Invalid organization or actor.");
  const membership = await db.membership.findFirst({
    where: {
      organizationId: actor.organizationId,
      userId: actor.userId,
    },
    select: { role: true },
  });
  if (!membership || membership.role !== actor.role)
    fail("Organization membership required.");
  if (mutation && !["OWNER", "ADMIN"].includes(membership.role))
    fail("Only administrators can manage domain proof challenges.");
}
async function audit(tx: Prisma.TransactionClient,
  actor: ExposureAuthorizationActor,
  authorizationId: string,
  revision: number,
  action: string,
  digest: string) {
  await tx.auditEvent.create({
    data: {
      organizationId: actor.organizationId,
      actorType: "USER", actorUserId: actor.userId,
      action: "EXPOSURE_AUTHORIZATION_" + action,
      resourceType: "EXPOSURE_DOMAIN_AUTHORIZATION",
      resourceId: authorizationId,
      metadata: {
        revision, challengeDigest: digest,
        operationsAgainstDomain: 0,
        independentlyConfirmedOwnership: false,
        customerSignatureVerified: false,
        storedBearerTokens: 0,
      },
    },
  });
}
export class ExposureAuthorizationService {
  async execute(actor: ExposureAuthorizationActor,
    raw: unknown): Promise<ExposureAuthorizationResult> {
    const command = parseCommand(raw);
    const mutation = ["ISSUE","REPLACE","REVOKE","EXPIRE",
      "VERIFY_DNS"]
      .includes(command.operation);
    await authorize(actor, mutation);
    const data = await this.dispatch(actor, command);
    return {
      schema: "cyberpilot.exposure.authorization.service.v1",
      organizationId: actor.organizationId,
      operation: command.operation, data,
      httpRequestsMade: 0, dnsQueriesMade:
        command.operation === "VERIFY_DNS" ?
          ((data as { liveDnsQueryCount?: number }).liveDnsQueryCount ?? 0) : 0,
      portScansMade: 0, signedCustomerApproval: false,
      legacyCyberScoreModified: false,
    };
  }
  private async dispatch(
    actor: ExposureAuthorizationActor,
    command: ExposureAuthorizationCommand,
  ): Promise<unknown> {
    const organizationId = actor.organizationId;
    if (command.operation === "LIST") {
      const rows = await db.exposureDomainAuthorization.findMany({
        where: { organizationId },
        orderBy: [{ updatedAt: "desc" }, { domain: "asc" }],
        take: command.limit ?? 30,
      });
      return {
        items: rows.map(view),
        authorizedActiveScans: 0,
        otherOrganizationsIncluded: false,
      };
    }
    if (command.operation === "HISTORY") {
      const row = await db.exposureDomainAuthorization.findFirst({
        where: { organizationId, domain: command.domain! },
      });
      if (!row) fail("Domain authorization not found.");
      const events = await db.exposureAuthorizationEvent.findMany({
        where: { organizationId, authorizationId: row.id },
        orderBy: { revision: "desc" },
        take: command.limit ?? 30,
      });
      return {
        domain: row.domain,
        events: events.map(item => ({
          revision: item.revision,
          action: item.action,
          priorState: item.priorState,
          newState: item.newState,
          evidenceDigest: item.evidenceDigest,
          actorUserId: item.actorUserId,
          at: item.createdAt.toISOString(),
          externalVerificationClaimed: false,
        })),
        providerLookupsPerformed: 0,
      };
    }
    if (command.operation === "READ") {
      const row = await db.exposureDomainAuthorization.findFirst({
        where: { organizationId, domain: command.domain! },
      });
      if (!row) fail("Domain authorization not found.");
      return { authorization: view(row), proofTokenAccessible: false };
    }
    if (command.operation === "VERIFY_DNS") {
      const row = await db.exposureDomainAuthorization.findFirst({
        where: {
          organizationId,
          domain: command.domain!,
        },
      });
      if (!row || row.revision !== command.expectedRevision)
        throw new ExposureAuthorizationConflict();
      if (row.state !== "PENDING" || row.method !== "DNS_TOKEN")
        fail("Only pending DNS challenges can be verified.");
      const checkedAt = new Date().toISOString();
      const observed = await verifyExposureDnsProof({
        organizationId, domain: row.domain,
        method: "DNS_TOKEN",
        token: command.proofToken!,
        challengeDigest: row.challengeDigest,
        expiresAt: row.challengeExpiresAt.toISOString(),
        checkedAt,
      });
      const classified = classifyExposureProofForPersisting(observed);
      const revision = row.revision + 1;
      const result = await db.$transaction(async tx => {
        const saved = await tx.exposureDomainAuthorization.update({
          where: { id: row.id, revision: row.revision },
          data: {
            revision, state: classified.status,
            lastCheckedAt: new Date(checkedAt),
            verifiedAt: classified.status === "VERIFIED" ?
              new Date(checkedAt) : null,
            evidenceDigest: observed.responseDigest,
            actorUserId: actor.userId,
          },
        });
        await tx.exposureAuthorizationEvent.create({
          data: {
            organizationId, authorizationId: saved.id,
            revision, action: "VERIFY_DNS",
            priorState: row.state, newState: saved.state,
            evidenceDigest: observed.responseDigest,
            actorUserId: actor.userId,
          },
        });
        await audit(tx, actor, saved.id, revision,
          "VERIFY_DNS", row.challengeDigest);
        return saved;
      }, { isolationLevel: "Serializable" });
      return {
        authorization: view(result),
        proofResult: {
          ...observed,
          // Neither the challenge nor plaintext TXT leaves this service.
          responseDigest: observed.responseDigest,
        },
        legalConsentAttested: false,
        portScanningAuthorized: false,
        liveDnsQueryCount: observed.networkQueriesPerformed,
      };
    }
    return db.$transaction(async tx => {
      const prior = await tx.exposureDomainAuthorization.findUnique({
        where: { organizationId_domain: {
          organizationId, domain: command.domain!,
        } },
      });
      if (!prior && command.expectedRevision !== 0 ||
          prior && command.expectedRevision !== prior.revision)
        throw new ExposureAuthorizationConflict();
      const next = (prior?.revision ?? 0) + 1;
      const action = command.operation;
      if ((action === "REVOKE" || action === "EXPIRE") && !prior)
        fail("Cannot revoke an unissued challenge.");
      if (action === "ISSUE" && prior)
        fail("Challenge exists; replace with optimistic revision.");
      if (action === "REPLACE" && !prior)
        fail("Replace requires an issued challenge.");
      const now = new Date();
      let challenge: ReturnType<typeof prepareExposureAuthorizationChallenge>
        | null = null;
      let challengeDigest = prior?.challengeDigest ?? "";
      let state: ExposureAuthorizationRecord["state"] = "PENDING";
      let expiresAt = prior?.challengeExpiresAt ?? now;
      let method = prior?.method ?? "DNS_TOKEN";
      if (action === "ISSUE" || action === "REPLACE") {
        // Cryptographically random challenge is returned once.
        const token = randomBytes(32).toString("hex");
        const request: ExposureAuthorizationRequest = {
          schema: "cyberpilot.exposure.domain.authorization.request.v1",
          organizationId, domain: command.domain!,
          method: command.method!,
          token, issuedAt: now.toISOString(),
          expiresAt: new Date(now.getTime() +
            30 * 60000).toISOString(),
          issuedBy: actor.userId,
          purpose: "PASSIVE_EXTERNAL_OBSERVATION",
          allowActivePortScanning: false,
          allowSubdomainEnumeration: false,
          allowThirdPartyHost: false,
        };
        challenge = prepareExposureAuthorizationChallenge(request);
        challengeDigest = challenge.challengeDigest;
        expiresAt = new Date(challenge.expiresAt);
        method = command.method!;
      } else if (action === "REVOKE") state = "REVOKED";
      else state = "EXPIRED";
      const record = prior ?
        await tx.exposureDomainAuthorization.update({
          where: { id: prior.id, revision: command.expectedRevision! },
          data: {
            revision: next, state, method,
            challengeDigest, challengeExpiresAt: expiresAt,
            verifiedAt: null,
            evidenceDigest: null,
            lastCheckedAt: null,
            revokedAt: state === "REVOKED" ? now : null,
            actorUserId: actor.userId,
          },
        }) :
        await tx.exposureDomainAuthorization.create({
          data: {
            organizationId, domain: command.domain!,
            revision: next, state, method,
            challengeDigest, challengeExpiresAt: expiresAt,
            actorUserId: actor.userId,
          },
        });
      await tx.exposureAuthorizationEvent.create({
        data: {
          organizationId, authorizationId: record.id,
          revision: next,
          action,
          priorState: prior?.state ?? "NONE",
          newState: state,
          evidenceDigest: null,
          actorUserId: actor.userId,
        },
      });
      await audit(tx, actor, record.id, next,
        action, challengeDigest);
      return {
        authorization: view(record),
        challenge, // Never persisted; caller must arrange proof placement.
        requiresTrustedCollectorVerification: true,
        scannedDomain: false,
        ownershipVerified: false,
      };
    }, { isolationLevel: "Serializable" });
  }
}
