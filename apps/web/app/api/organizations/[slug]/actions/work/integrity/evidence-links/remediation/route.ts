import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { canReadWork, WorkInputError } from "../../../../../../../../../lib/remediation-work-input";
import { listCompleteIntegrityWorkLinkState } from "../../../../../../../../../lib/work-integrity-evidence-links";
import { parseIntegrityEvidenceCoveragePolicy } from "../../../../../../../../../lib/work-integrity-evidence-coverage";
import { parseIntegrityEvidencePortfolioInput } from "../../../../../../../../../lib/work-integrity-evidence-portfolio";
import { parseIntegrityPortfolioRiskWeights } from "../../../../../../../../../lib/work-integrity-portfolio-risk";
import {
  planIntegrityRemediationFromEvents, parseIntegrityRemediationPlanQuery,
  queryIntegrityRemediationPlan,
} from "../../../../../../../../../lib/work-integrity-remediation-plan";
import {
  buildIntegrityRemediationHistory, parseIntegrityRemediationHistoryQuery,
  queryIntegrityRemediationHistory, summarizeIntegrityRemediationHistory,
} from "../../../../../../../../../lib/work-integrity-remediation-history";
type Context = { params: Promise<{ slug: string }> };
const headers = {
  "Cache-Control": "private, no-store",
  "X-Content-Type-Options": "nosniff",
};
function failure(error: unknown) {
  if (error instanceof WorkInputError)
    return NextResponse.json({ code: error.code, error: error.message }, {
      status: { INVALID: 400, FORBIDDEN: 403, MISSING: 404, CONFLICT: 409 }[error.code],
      headers,
    });
  console.error("Integrity remediation planning failed",
    error instanceof Error ? error.message : "unknown");
  return NextResponse.json({
    error: "Unable to evaluate integrity remediation.",
  }, { status: 500, headers });
}
function parseRequest(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new WorkInputError("INVALID", "Expected remediation request object.");
  const raw = value as Record<string, unknown>;
  if (Object.keys(raw).some(x => ![
    "portfolio", "view", "weights", "query", "checkpoints",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown remediation request field.");
  const input = parseIntegrityEvidencePortfolioInput(raw.portfolio);
  const policies = input.policies.map(x =>
    parseIntegrityEvidenceCoveragePolicy(x));
  const view = raw.view ?? "plan";
  if (!["plan", "candidates", "history", "history-summary", "history-page"]
    .includes(view))
    throw new WorkInputError("INVALID", "Invalid remediation view.");
  if (raw.checkpoints !== undefined && ![
    "history", "history-summary", "history-page",
  ].includes(view))
    throw new WorkInputError("INVALID", "Checkpoints require history view.");
  if (raw.query !== undefined && ![
    "candidates", "history-page",
  ].includes(view))
    throw new WorkInputError("INVALID", "Query requires paginated view.");
  const weights = parseIntegrityPortfolioRiskWeights(raw.weights);
  return {
    input: { ...input, policies }, view, weights,
    query: raw.query, checkpoints: raw.checkpoints,
  };
}
export async function POST(request: NextRequest, { params }: Context) {
  try {
    const { slug } = await params;
    const { membership } = await requireOrganizationAccess(slug);
    if (!canReadWork(membership.role))
      throw new WorkInputError("FORBIDDEN", "Organization access required.");
    if (!/^application\/json(?:\s*;|\s*$)/i.test(
      request.headers.get("content-type") ?? ""))
      throw new WorkInputError("INVALID", "JSON content type required.");
    const length = request.headers.get("content-length");
    if (length && (!/^\d+$/.test(length) || Number(length) > 100000))
      throw new WorkInputError("INVALID", "Remediation request too large.");
    const body = await request.text();
    if (body.length > 100000)
      throw new WorkInputError("INVALID", "Remediation request too large.");
    let input: unknown;
    try { input = JSON.parse(body); } catch {
      throw new WorkInputError("INVALID", "Malformed JSON.");
    }
    const parsed = parseRequest(input);
    const state = await listCompleteIntegrityWorkLinkState(
      membership.organization.id, parsed.input.captureId);
    if (["history", "history-summary", "history-page"].includes(parsed.view)) {
      if (!Array.isArray(parsed.checkpoints))
        throw new WorkInputError("INVALID", "History checkpoints required.");
      const history = buildIntegrityRemediationHistory(
        parsed.input, state.events, parsed.checkpoints, parsed.weights);
      if (parsed.view === "history")
        return NextResponse.json({ history }, { headers });
      if (parsed.view === "history-summary")
        return NextResponse.json({
          summary: summarizeIntegrityRemediationHistory(history),
        }, { headers });
      const query = parseIntegrityRemediationHistoryQuery(parsed.query ?? {});
      return NextResponse.json({
        result: queryIntegrityRemediationHistory(history, query),
      }, { headers });
    }
    const result = planIntegrityRemediationFromEvents(
      parsed.input, state.events, parsed.weights);
    if (parsed.view === "plan")
      return NextResponse.json({ result }, { headers });
    const query = parseIntegrityRemediationPlanQuery(parsed.query ?? {});
    return NextResponse.json({
      result: queryIntegrityRemediationPlan(result.plan, query),
    }, { headers });
  } catch (error) { return failure(error); }
}
