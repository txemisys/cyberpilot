import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from
  "../../../../../lib/organizations";
import {
  assessBaselineOfflineV2, buildBaselineReportV2,
  exportBaselineReportV2, buildBaselineActionPlanV2,
  buildPhase2OfflinePortfolio, verifyPhase2OfflinePortfolio,
  exportPhase2Portfolio, BASELINE_IG1_QUESTIONS,
  type BaselineSubmission, type ExposureOfflineEnvelope,
} from "@cyberpilot/risk-engine";
import { createHash } from "node:crypto";

type Params = { params: Promise<{ slug: string }> };
const cacheHeaders = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
const MAX_SIZE = 160 * 1024;
function fail(message: string, status: number) {
  return NextResponse.json({
    error: message, securityCertified: false,
    liveProviderAuthenticated: false,
    legacyCyberScoreModified: false,
  }, { status, headers: cacheHeaders });
}
function limitedString(value: unknown, max = 128) {
  return typeof value === "string" &&
    value.length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value);
}
function digest(text: string) {
  return createHash("sha256").update(text).digest("hex");
}
function parseBody(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw Error("Invalid Phase 2 request envelope.");
  const raw = value as Record<string, unknown>;
  const validKeys = [
    "operation", "questionnaire", "exposure", "exportFormat",
  ];
  if (Object.keys(raw).some(k => !validKeys.includes(k)))
    throw Error("Unexpected Phase 2 request fields.");
  if (!["BASELINE", "PORTFOLIO", "QUESTIONNAIRE"].includes(
      String(raw.operation)))
    throw Error("Unsupported Phase 2 request.");
  if (raw.exportFormat !== undefined &&
      !["JSON", "CSV", "MARKDOWN"].includes(
        String(raw.exportFormat)))
    throw Error("Invalid export format.");
  return raw;
}
export async function POST(request: NextRequest,
  context: Params) {
  try {
    const { slug } = await context.params;
    const { session, membership } =
      await requireOrganizationAccess(slug);
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) ||
        Number(length) > MAX_SIZE))
      return fail("Phase 2 request exceeds size limit.", 413);
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin)
      return fail("Cross-origin operation is not permitted.", 403);
    const type = request.headers.get("content-type")?.split(";")[0]?.trim();
    if (type !== "application/json")
      return fail("JSON content type required.", 415);
    const body = await request.text();
    if (Buffer.byteLength(body, "utf8") > MAX_SIZE)
      return fail("Phase 2 request exceeds size limit.", 413);
    const raw = parseBody(JSON.parse(body));
    if (raw.operation === "QUESTIONNAIRE")
      return NextResponse.json({
        version: 1, questions: BASELINE_IG1_QUESTIONS,
        certificationClaimed: false,
        noM365Required: true,
      }, { headers: cacheHeaders });
    if (!raw.questionnaire ||
        typeof raw.questionnaire !== "object" ||
        Array.isArray(raw.questionnaire))
      return fail("Questionnaire submission is required.", 400);
    const questionnaire = raw.questionnaire as BaselineSubmission;
    if (questionnaire.organizationId !== membership.organization.id)
      return fail("Cross-organization submission rejected.", 403);
    const now = new Date().toISOString();
    const snapshotId = "phase2-" + digest(
      membership.organization.id + body + now).slice(0, 32);
    const options = {
      organizationId: membership.organization.id,
      snapshotId, evaluatedAt: now,
      completedBy: session.user.id,
      notePolicy: "DISCARD_CONTENT" as const,
      referencePolicy: "OPAQUE_IDENTIFIERS_ONLY" as const,
      maxActions: 100,
    };
    const baseline = assessBaselineOfflineV2(questionnaire, options);
    const baselineReport = buildBaselineReportV2(baseline);
    const plan = buildBaselineActionPlanV2(baselineReport);
    const format = raw.exportFormat as
      "JSON" | "CSV" | "MARKDOWN" | undefined;
    if (raw.operation === "BASELINE") {
      const exported = format ?
        exportBaselineReportV2(baselineReport, format) : null;
      return NextResponse.json({
        schema: "cyberpilot.phase2.web.baseline.v1",
        report: baselineReport, actionPlan: plan,
        exported, previewOnly: true,
        rawNotesRetained: false,
        providerNetworkRequests: 0,
        customerComplianceCertified: false,
        legacyCyberScoreModified: false,
      }, { headers: cacheHeaders });
    }
    if (!Array.isArray(raw.exposure) ||
        raw.exposure.length > 20)
      return fail("Exposure observations must be a bounded array.", 400);
    // Client assertions cannot establish independent ownership.
    // Passive inputs are intentionally downgraded to untrusted
    // offline evidence even if a client sends forged LIVE flags.
    const external = raw.exposure as ExposureOfflineEnvelope[];
    const exposure = external.map(record => {
      if (record.organizationId !== membership.organization.id ||
          !record.authorization ||
          record.authorization.organizationId !== membership.organization.id)
        throw Error("Exposure tenant scope mismatch.");
      return {
        ...record, sourceIsSynthetic: true as const,
        claimsVerifiedProductionSecurity: false as const,
        networkRequestsByEvaluator: 0 as const,
        dynamicLookupsByEvaluator: 0 as const,
        thirdPartyScanningAuthorized: false as const,
        authorization: {
          ...record.authorization,
          verificationMethod: "DECLARATION" as const,
          verified: false,
          verifiedAt: null,
          externalOwnershipIndependentlyVerified: false,
          canPerformActiveScanning: false as const,
        },
      };
    });
    const portfolio = buildPhase2OfflinePortfolio({
      schema: "cyberpilot.phase2.portfolio.input.v1",
      organizationId: membership.organization.id,
      snapshotId, evaluatedAt: now, actorId: session.user.id,
      exposure, baseline: questionnaire,
      sourceMode: "OFFLINE_ONLY",
      liveNetworkRequestsAllowed: false,
      oauthTokensProvided: false,
      authorizedLiveTenantClaimed: false,
      maximumActions: 100,
    });
    if (!verifyPhase2OfflinePortfolio(portfolio).valid)
      throw Error("Portfolio failed local source verification.");
    const exported = format ?
      exportPhase2Portfolio(portfolio, format) : null;
    return NextResponse.json({
      schema: "cyberpilot.phase2.web.portfolio.v1",
      report: portfolio,
      exported, previewOnly: true,
      providerNetworkRequests: 0,
      customerComplianceCertified: false,
      legacyCyberScoreModified: false,
    }, { headers: cacheHeaders });
  } catch (error) {
    const message = error instanceof Error ?
      error.message : "Phase 2 evaluation failed.";
    if (/Invalid|Unknown|Unsupported|Cross-organization|Cross-tenant|Exposure|Baseline|source|evidence|not permitted|rejected|mismatch/i
      .test(message))
      return fail("Invalid or out-of-scope offline evidence.", 400);
    return fail("Phase 2 evaluation unavailable.", 503);
  }
}
export async function GET() {
  return fail("Use authenticated POST for Phase 2 operations.", 405);
}
export async function DELETE() {
  return fail("This offline preview cannot delete any customer records.", 405);
}
