import { createHash, timingSafeEqual } from "node:crypto";
import {
  GoogleLabError, GoogleLabOnboardingService,
  buildNeutralGoogleBundle, verifyNeutralGoogleBundle,
  compareNeutralGoogleBundles, neutralGoogleJson,
  neutralGoogleCsv, verifyNeutralGoogleComparison,
  type GoogleLabScope, type GoogleLabCommand,
  type NeutralGoogleBundle,
  type GoogleCapability,
} from "@cyberpilot/integrations/google-workspace";
import { PrismaGoogleLabRepository } from
  "./google-lab-prisma-repository";
import {
  persistGoogleOfflineSnapshot, readGoogleOfflineSnapshot,
  listGoogleOfflineSnapshots, auditGoogleOfflineSnapshot,
  diffStoredGoogleSnapshots, inspectGoogleSnapshotRetention,
  buildGoogleStoredHistory, parseGoogleSnapshotList,
} from "./google-offline-snapshot-service";

export type GoogleWorkspaceOperation =
  "CREATE_LAB" | "GET_LAB" | "LIST_LAB" |
  "MUTATE_LAB" | "AUDIT_LAB" | "ELIGIBILITY" |
  "SAVE_FIXTURE" | "LIST_SNAPSHOTS" |
  "READ_SNAPSHOT" | "AUDIT_SNAPSHOT" |
  "DIFF_SNAPSHOTS" | "RETENTION_PREVIEW" |
  "SNAPSHOT_HISTORY" | "NEUTRAL_BUNDLE" |
  "NEUTRAL_JSON" | "NEUTRAL_CSV" |
  "NEUTRAL_COMPARE";
export type GoogleWorkspaceRequest = {
  operation: GoogleWorkspaceOperation;
  input: unknown;
  evaluatedAt?: string;
};
export type GoogleWorkspaceResponse = {
  schema: "cyberpilot.google.offline.workspace.response.v1";
  organizationId: string;
  operation: GoogleWorkspaceOperation;
  evaluatedAt: string;
  data: unknown;
  digest: string;
  boundaries: {
    scope: "OFFLINE_LAB_DEVELOPMENT_ONLY";
    externalGoogleRequests: 0;
    externalAccountWrites: 0;
    sourceIsCustomerProof: false;
    consentIsRealGoogleOauth: false;
    liveProviderValidated: false;
    canonicalCyberScoreModified: false;
    customerBusinessApprovalGranted: false;
    dataAccessAuthorizedByMembership: true;
  };
  warnings: string[];
};
export const GOOGLE_OFFLINE_OPERATIONS:
  readonly GoogleWorkspaceOperation[] = [
    "CREATE_LAB", "GET_LAB", "LIST_LAB",
    "MUTATE_LAB", "AUDIT_LAB", "ELIGIBILITY",
    "SAVE_FIXTURE", "LIST_SNAPSHOTS",
    "READ_SNAPSHOT", "AUDIT_SNAPSHOT",
    "DIFF_SNAPSHOTS", "RETENTION_PREVIEW",
    "SNAPSHOT_HISTORY", "NEUTRAL_BUNDLE",
    "NEUTRAL_JSON", "NEUTRAL_CSV",
    "NEUTRAL_COMPARE",
  ];
const warnings = [
  "Google Workspace is only simulated through offline fixtures.",
  "No LIVE Google OAuth or external provider identity is authenticated.",
  "This response does not attest a real administrator approval.",
  "The neutral adapter does not update canonical CyberScore.",
  "Risk findings may be uncertain, partial or inapplicable.",
  "Authorization to change accounts must be obtained separately.",
];
function invalid(message: string): never {
  throw new GoogleLabError("INVALID", message);
}
function object(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    invalid("Google offline workspace input must be an object.");
  return value as Record<string, unknown>;
}
function str(value: unknown, label: string) {
  if (typeof value !== "string" ||
      !/^[a-zA-Z0-9_-]{5,128}$/.test(value))
    invalid("Invalid Google offline " + label + ".");
  return value;
}
function datetime(value: unknown) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d\d-\d\dT/.test(value) ||
      !Number.isFinite(Date.parse(value)))
    invalid("Invalid Google offline evaluation date.");
  return new Date(value).toISOString();
}
function hash(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function same(a: unknown, b: unknown) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function role(scope: GoogleLabScope, writable = false) {
  if (!["OWNER", "ADMIN", "MEMBER", "AUDITOR"].includes(scope.role))
    throw new GoogleLabError("FORBIDDEN", "Unknown organization role.");
  if (writable && scope.role !== "OWNER" && scope.role !== "ADMIN")
    throw new GoogleLabError("FORBIDDEN",
      "Only administrators may write Google LAB evidence.");
}
export function parseGoogleWorkspaceRequest(
  raw: unknown,
): GoogleWorkspaceRequest {
  const value = object(raw);
  if (Object.keys(value).some(key => ![
    "operation", "input", "evaluatedAt",
  ].includes(key)))
    invalid("Unexpected Google workspace request field.");
  if (!GOOGLE_OFFLINE_OPERATIONS.includes(
    value.operation as GoogleWorkspaceOperation))
    invalid("Unknown Google workspace operation.");
  if (value.input === undefined)
    invalid("Google workspace operation input missing.");
  if (value.evaluatedAt !== undefined)
    datetime(value.evaluatedAt);
  return {
    operation: value.operation as GoogleWorkspaceOperation,
    input: value.input,
    ...(value.evaluatedAt !== undefined ?
      { evaluatedAt: datetime(value.evaluatedAt) } : {}),
  };
}
function response(
  scope: GoogleLabScope, operation: GoogleWorkspaceOperation,
  evaluatedAt: string, data: unknown,
): GoogleWorkspaceResponse {
  const boundaries = {
    scope: "OFFLINE_LAB_DEVELOPMENT_ONLY" as const,
    externalGoogleRequests: 0 as const,
    externalAccountWrites: 0 as const,
    sourceIsCustomerProof: false as const,
    consentIsRealGoogleOauth: false as const,
    liveProviderValidated: false as const,
    canonicalCyberScoreModified: false as const,
    customerBusinessApprovalGranted: false as const,
    dataAccessAuthorizedByMembership: true as const,
  };
  const canonical = {
    schema: "cyberpilot.google.offline.workspace.response.v1" as const,
    organizationId: scope.organizationId,
    operation, evaluatedAt, data, boundaries,
    warnings: [...warnings],
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyGoogleWorkspaceResponse(
  result: GoogleWorkspaceResponse,
) {
  const { digest, ...canonical } = result;
  const issues: string[] = [];
  if (!same(digest, hash(canonical)))
    issues.push("Workspace response was altered.");
  if (result.boundaries.externalGoogleRequests !== 0 ||
      result.boundaries.externalAccountWrites !== 0 ||
      result.boundaries.liveProviderValidated ||
      result.boundaries.sourceIsCustomerProof ||
      result.boundaries.canonicalCyberScoreModified ||
      result.boundaries.consentIsRealGoogleOauth ||
      result.boundaries.customerBusinessApprovalGranted)
    issues.push("Workspace claimed a prohibited external or business action.");
  if (!GOOGLE_OFFLINE_OPERATIONS.includes(result.operation))
    issues.push("Unknown Google workspace operation.");
  if (!Array.isArray(result.warnings) ||
      result.warnings.length < warnings.length)
    issues.push("Workspace limitations removed.");
  return { valid: issues.length === 0, issues };
}
export function parseNeutralBundleQuery(raw: unknown) {
  const x = object(raw);
  if (Object.keys(x).some(key => ![
    "snapshotId", "expectedSourceDigest",
    "includeControls", "includeFindings",
  ].includes(key)))
    invalid("Unexpected neutral bundle selection.");
  if (x.includeControls !== undefined &&
      typeof x.includeControls !== "boolean" ||
      x.includeFindings !== undefined &&
      typeof x.includeFindings !== "boolean")
    invalid("Invalid neutral bundle output option.");
  if (x.expectedSourceDigest !== undefined &&
      (typeof x.expectedSourceDigest !== "string" ||
       !/^[a-f0-9]{64}$/.test(x.expectedSourceDigest)))
    invalid("Neutral source digest is malformed.");
  return {
    snapshotId: str(x.snapshotId, "snapshot ID"),
    expectedSourceDigest: x.expectedSourceDigest as string | undefined,
    includeControls: x.includeControls !== false,
    includeFindings: x.includeFindings !== false,
  };
}
async function readNeutral(scope: GoogleLabScope, input: unknown) {
  const selection = parseNeutralBundleQuery(input);
  const snapshot = await readGoogleOfflineSnapshot(
    scope, selection.snapshotId);
  if (selection.expectedSourceDigest &&
      snapshot.metadata.sourceDigest !==
        selection.expectedSourceDigest)
    throw new GoogleLabError("CONFLICT",
      "Neutral snapshot source changed since last review.");
  const bundle = buildNeutralGoogleBundle(snapshot.assessment);
  if (!verifyNeutralGoogleBundle(bundle).valid)
    throw new GoogleLabError("CONFLICT",
      "Neutral evidence projection failed integrity validation.");
  if (bundle.organizationId !== scope.organizationId)
    throw new GoogleLabError("MISSING",
      "Neutral evidence does not belong to this organization.");
  return { bundle, selection, snapshotId: snapshot.metadata.id };
}
export function listGoogleOfflineOperations() {
  return GOOGLE_OFFLINE_OPERATIONS.map(operation => ({
    operation,
    category: [
      "CREATE_LAB", "MUTATE_LAB",
    ].includes(operation) ? "LAB_MUTATION" :
      operation === "SAVE_FIXTURE" ?
        "SYNTHETIC_SNAPSHOT_WRITE" :
        operation.startsWith("NEUTRAL_") ?
          "NEUTRAL_EVIDENCE" : "READ_ONLY",
    requiresRealGoogleOAuth: false,
    mayModifyGoogleAccount: false,
    requiresCustomerBusinessApproval: false,
    requiresOrganizationMembership: true,
    exportIncludesProviderSecrets: false,
  }));
}
export class GoogleOfflineWorkspace {
  private readonly lab = new GoogleLabOnboardingService(
    new PrismaGoogleLabRepository());
  async execute(
    scope: GoogleLabScope,
    raw: unknown,
    now: Date = new Date(),
  ): Promise<GoogleWorkspaceResponse> {
    const request = parseGoogleWorkspaceRequest(raw);
    const evaluatedAt = request.evaluatedAt ?? now.toISOString();
    datetime(evaluatedAt);
    const input = request.input;
    let data: unknown;
    switch (request.operation) {
      case "CREATE_LAB":
        role(scope, true);
        data = await this.lab.create(scope, input);
        break;
      case "GET_LAB":
        role(scope);
        data = await this.lab.get(scope,
          str(object(input).connectionId, "connection ID"),
          evaluatedAt);
        break;
      case "LIST_LAB":
        role(scope);
        data = await this.lab.list(scope, input);
        break;
      case "MUTATE_LAB":
        role(scope, true);
        data = await this.lab.mutate(scope,
          input as GoogleLabCommand);
        break;
      case "AUDIT_LAB":
        role(scope);
        data = await this.lab.audit(scope,
          str(object(input).connectionId, "connection ID"),
          evaluatedAt);
        break;
      case "ELIGIBILITY": {
        role(scope);
        const x = object(input);
        if (!Array.isArray(x.capabilities) ||
            x.capabilities.some(c => ![
              "DIRECTORY_USERS", "DIRECTORY_DOMAINS",
              "DIRECTORY_ORGANIZATION_UNITS", "REPORTS_LOGIN",
              "REPORTS_ADMIN", "USER_MFA_ATTRIBUTES",
            ].includes(String(c))))
          invalid("Unknown requested Google capability.");
        data = await this.lab.eligibility(
          scope, str(x.connectionId, "connection ID"),
          evaluatedAt, x.capabilities as GoogleCapability[]);
        break;
      }
      case "SAVE_FIXTURE":
        role(scope, true);
        data = await persistGoogleOfflineSnapshot(scope, input);
        break;
      case "LIST_SNAPSHOTS":
        role(scope);
        data = await listGoogleOfflineSnapshots(
          scope, parseGoogleSnapshotList(input), evaluatedAt);
        break;
      case "READ_SNAPSHOT":
        role(scope);
        data = await readGoogleOfflineSnapshot(
          scope, str(object(input).snapshotId, "snapshot ID"));
        break;
      case "AUDIT_SNAPSHOT":
        role(scope);
        data = await auditGoogleOfflineSnapshot(
          scope, str(object(input).snapshotId, "snapshot ID"),
          evaluatedAt);
        break;
      case "DIFF_SNAPSHOTS":
        role(scope);
        data = await diffStoredGoogleSnapshots(
          scope,
          str(object(input).baselineId, "baseline snapshot ID"),
          str(object(input).currentId, "current snapshot ID"));
        break;
      case "RETENTION_PREVIEW":
        role(scope, true);
        data = await inspectGoogleSnapshotRetention(
          scope, evaluatedAt,
          object(input).limit === undefined ? 100 :
            object(input).limit as number);
        break;
      case "SNAPSHOT_HISTORY": {
        role(scope);
        const x = object(input);
        data = await buildGoogleStoredHistory(
          scope, str(x.connectionId, "connection ID"),
          x.limit === undefined ? 50 : x.limit as number);
        break;
      }
      case "NEUTRAL_BUNDLE": {
        role(scope);
        const { bundle, selection, snapshotId } =
          await readNeutral(scope, input);
        data = {
          snapshotId, organizationId: scope.organizationId,
          sourceDigest: bundle.sourceDigest,
          coverage: bundle.coverage,
          summary: bundle.summary,
          controls: selection.includeControls ?
            bundle.controls : [],
          findings: selection.includeFindings ?
            bundle.findings : [],
          projectionPartial: !selection.includeControls ||
            !selection.includeFindings,
          originalBundleDigest: bundle.digest,
          noCanonicalScoreUpdate: true as const,
        };
        break;
      }
      case "NEUTRAL_JSON": {
        role(scope);
        const { bundle, snapshotId } =
          await readNeutral(scope, input);
        data = {
          snapshotId, export: neutralGoogleJson(bundle),
          byteLength: Buffer.byteLength(
            neutralGoogleJson(bundle), "utf8"),
          sourceDigest: bundle.sourceDigest,
          customerConsentVerified: false as const,
        };
        break;
      }
      case "NEUTRAL_CSV": {
        role(scope);
        const { bundle, snapshotId } =
          await readNeutral(scope, input);
        data = {
          snapshotId, export: neutralGoogleCsv(bundle),
          sourceDigest: bundle.sourceDigest,
          csvFormulaProtectionEnabled: true as const,
          customerIdentityExported: false as const,
        };
        break;
      }
      case "NEUTRAL_COMPARE": {
        role(scope);
        const x = object(input);
        const first = await readNeutral(scope, {
          snapshotId: str(x.baselineId, "baseline ID"),
        });
        const second = await readNeutral(scope, {
          snapshotId: str(x.currentId, "current ID"),
        });
        if (first.snapshotId === second.snapshotId)
          invalid("Comparison requires distinct snapshots.");
        const comparison = compareNeutralGoogleBundles(
          first.bundle, second.bundle);
        if (!verifyNeutralGoogleComparison(comparison).valid)
          throw new GoogleLabError("CONFLICT",
            "Neutral evidence comparison verification failed.");
        data = {
          comparison, baselineId: first.snapshotId,
          currentId: second.snapshotId,
          noRemediationProven: true as const,
        };
        break;
      }
      default:
        invalid("Unsupported offline workspace operation.");
    }
    const final = response(scope, request.operation,
      evaluatedAt, data);
    if (!verifyGoogleWorkspaceResponse(final).valid)
      throw new GoogleLabError("CONFLICT",
        "Workspace response digest validation failed.");
    return final;
  }
}
export function googleOfflineWorkspaceManifest(
  result: GoogleWorkspaceResponse,
) {
  if (!verifyGoogleWorkspaceResponse(result).valid)
    invalid("Cannot export altered Google workspace operation.");
  return {
    schema: "cyberpilot.google.workspace.manifest.v1" as const,
    organizationId: result.organizationId,
    operation: result.operation,
    evaluatedAt: result.evaluatedAt,
    responseDigest: result.digest,
    sourceBoundary: "OFFLINE_LAB_DEVELOPMENT_ONLY" as const,
    externalProviderContacted: false as const,
    providerOauthConsentVerified: false as const,
    customerApprovalVerified: false as const,
    canonicalScoreChanged: false as const,
    accountActionsPerformed: 0 as const,
    exportedToThirdParty: false as const,
  };
}
