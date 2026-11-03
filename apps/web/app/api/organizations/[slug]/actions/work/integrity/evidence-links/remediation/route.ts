import { exportIntegrityExecutionCapacity, parseIntegrityExecutionCapacityExportOptions } from "../../../../../../../../../lib/work-integrity-remediation-execution-capacity-export";
import { forecastIntegrityExecutionCapacity, parseIntegrityExecutionCapacityForecastPolicy, parseIntegrityExecutionCapacityForecastQuery, queryIntegrityExecutionCapacityForecast } from "../../../../../../../../../lib/work-integrity-remediation-execution-capacity-forecast";
import { planIntegrityExecutionCapacity, parseIntegrityExecutionCapacityMembers, parseIntegrityExecutionCapacityPolicy, parseIntegrityExecutionCapacityQuery, queryIntegrityExecutionCapacity } from "../../../../../../../../../lib/work-integrity-remediation-execution-capacity";
import { prioritizeIntegrityExecutionRemediation, parseIntegrityExecutionRemediationQueuePolicy, parseIntegrityExecutionRemediationQueueQuery, queryIntegrityExecutionRemediationQueue } from "../../../../../../../../../lib/work-integrity-remediation-execution-queue";
import { buildIntegrityExecutionReadinessHistory, parseIntegrityExecutionReadinessHistoryQuery, queryIntegrityExecutionReadinessHistory } from "../../../../../../../../../lib/work-integrity-remediation-readiness-history";
import { evaluateIntegrityExecutionReadiness, parseIntegrityExecutionReadinessPolicy, parseIntegrityExecutionReadinessQuery, queryIntegrityExecutionReadiness } from "../../../../../../../../../lib/work-integrity-remediation-execution-readiness";
import { evaluateIntegrityExecutionControls, parseIntegrityExecutionControlPolicy } from "../../../../../../../../../lib/work-integrity-remediation-execution-controls";
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
import {
  buildIntegrityRemediationWorkspace,
  parseIntegrityRemediationDecisions,
  parseIntegrityRemediationDecisionPolicy,
  auditIntegrityRemediationDecisions,
} from "../../../../../../../../../lib/work-integrity-remediation-workspace";
import { parseIntegrityRemediationGatePolicy } from "../../../../../../../../../lib/work-integrity-remediation-gates";
import { parseIntegrityRemediationCapacity } from "../../../../../../../../../lib/work-integrity-remediation-capacity";
import {
  parseIntegrityRemediationSlaPolicy,
  evaluateIntegrityRemediationSla,
  parseIntegrityRemediationSlaQuery,
  queryIntegrityRemediationSla,
} from "../../../../../../../../../lib/work-integrity-remediation-sla";
import {
  parseIntegrityEscalationPolicy,
  parseIntegrityEscalationAcknowledgements,
  evaluateIntegrityEscalations,
  parseIntegrityEscalationQuery,
  queryIntegrityEscalations,
  buildIntegrityEscalationDeliveryManifest,
} from "../../../../../../../../../lib/work-integrity-remediation-escalation";
import {
  parseIntegrityRemediationExecutionEvents,
  buildIntegrityRemediationExecutionLedger,
  verifyIntegrityRemediationExecutionEvidence,
  parseIntegrityRemediationExecutionQuery,
  queryIntegrityRemediationExecution,
} from "../../../../../../../../../lib/work-integrity-remediation-execution";
import {
  buildIntegrityExecutionReviewHistory,
  buildIntegrityExecutionReviewAudit,
  buildIntegrityExecutionReviewMatrix,
  parseIntegrityExecutionReviewQuery,
  queryIntegrityExecutionReview,
} from "../../../../../../../../../lib/work-integrity-remediation-execution-review";
import {
  evaluateIntegrityExecutionPerformance,
  parseIntegrityExecutionPerformanceQuery,
  queryIntegrityExecutionPerformance,
} from "../../../../../../../../../lib/work-integrity-remediation-execution-performance";
import {
  reconcileIntegrityExecutionEvidence,
  parseIntegrityExecutionEvidenceQuery,
  queryIntegrityExecutionEvidence,
} from "../../../../../../../../../lib/work-integrity-remediation-evidence-provenance";
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
    "gatePolicy", "decisions", "decisionPolicy", "capacity", "exportRequest",
    "slaPolicy", "createdAt", "evaluatedAt", "escalationPolicy",
    "acknowledgements", "slaQuery", "escalationQuery",
    "executionEvents", "executionQuery", "executionCheckpoints",
    "executionReviewQuery", "executionPerformanceQuery",
    "executionEvidenceQuery", "executionReadinessPolicy", "executionReadinessQuery",
    "executionReadinessCheckpoints", "executionReadinessHistoryQuery",
    "executionQueuePolicy", "executionQueueQuery",
    "executionCapacityMembers", "executionCapacityPolicy", "executionCapacityQuery",
    "executionCapacityForecastPolicy", "executionCapacityForecastQuery",
    "executionCapacityExport",
  ].includes(x)))
    throw new WorkInputError("INVALID", "Unknown remediation request field.");
  const input = parseIntegrityEvidencePortfolioInput(raw.portfolio);
  const policies = input.policies.map(x =>
    parseIntegrityEvidenceCoveragePolicy(x));
  const view = raw.view ?? "plan";
  if (typeof view !== "string")
    throw new WorkInputError("INVALID", "Invalid remediation view.");
  if (!["plan", "candidates", "history", "history-summary", "history-page", "workspace"]
    .includes(view))
    throw new WorkInputError("INVALID", "Invalid remediation view.");
  if (raw.checkpoints !== undefined && ![
    "history", "history-summary", "history-page", "workspace",
  ].includes(view))
    throw new WorkInputError("INVALID", "Checkpoints require history view.");
  if (raw.query !== undefined && ![
    "candidates", "history-page",
  ].includes(view))
    throw new WorkInputError("INVALID", "Query requires paginated view.");
  if (view !== "workspace" && [
    "gatePolicy", "decisions", "decisionPolicy", "capacity", "exportRequest",
    "slaPolicy", "createdAt", "evaluatedAt", "escalationPolicy",
    "acknowledgements", "slaQuery", "escalationQuery",
    "executionEvents", "executionQuery", "executionCheckpoints",
    "executionReviewQuery", "executionPerformanceQuery",
    "executionEvidenceQuery",
  ].some(key => raw[key] !== undefined))
    throw new WorkInputError("INVALID", "Workspace options require workspace view.");
  const weights = parseIntegrityPortfolioRiskWeights(raw.weights);
  return {
    input: { ...input, policies }, view, weights,
    query: raw.query, checkpoints: raw.checkpoints,
    gatePolicy: raw.gatePolicy, decisions: raw.decisions,
    decisionPolicy: raw.decisionPolicy, capacity: raw.capacity,
    exportRequest: raw.exportRequest,
    slaPolicy: raw.slaPolicy, createdAt: raw.createdAt,
    evaluatedAt: raw.evaluatedAt, escalationPolicy: raw.escalationPolicy,
    acknowledgements: raw.acknowledgements,
    slaQuery: raw.slaQuery, escalationQuery: raw.escalationQuery,
    executionEvents: raw.executionEvents,
    executionQuery: raw.executionQuery,
    executionCheckpoints: raw.executionCheckpoints,
    executionReviewQuery: raw.executionReviewQuery,
    executionPerformanceQuery: raw.executionPerformanceQuery,
    executionEvidenceQuery: raw.executionEvidenceQuery,
    executionReadinessPolicy: raw.executionReadinessPolicy,
    executionReadinessQuery: raw.executionReadinessQuery,
    executionReadinessCheckpoints: raw.executionReadinessCheckpoints,
    executionReadinessHistoryQuery: raw.executionReadinessHistoryQuery,
    executionQueuePolicy: raw.executionQueuePolicy,
    executionQueueQuery: raw.executionQueueQuery,
    executionCapacityMembers: raw.executionCapacityMembers,
    executionCapacityPolicy: raw.executionCapacityPolicy,
    executionCapacityQuery: raw.executionCapacityQuery,
    executionCapacityForecastPolicy: raw.executionCapacityForecastPolicy,
    executionCapacityForecastQuery: raw.executionCapacityForecastQuery,
    executionCapacityExport: raw.executionCapacityExport,
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
    if (parsed.view === "workspace") {
      const decisions = parseIntegrityRemediationDecisions(parsed.decisions ?? []);
      const workspace = buildIntegrityRemediationWorkspace(
        parsed.input, state.events, {
          weights: parsed.weights,
          ...(parsed.checkpoints !== undefined ? {
            checkpoints: parsed.checkpoints as string[],
          } : {}),
          ...(parsed.gatePolicy !== undefined ? {
            gatePolicy: parseIntegrityRemediationGatePolicy(parsed.gatePolicy),
          } : {}),
          decisions,
          ...(parsed.capacity !== undefined ? {
            capacity: parseIntegrityRemediationCapacity(parsed.capacity),
          } : {}),
          ...(parsed.exportRequest !== undefined ? {
            exportRequest: parsed.exportRequest,
          } : {}),
        });
      const audit = auditIntegrityRemediationDecisions(
        workspace.plan, decisions,
        parseIntegrityRemediationDecisionPolicy(parsed.decisionPolicy));
      const executionEvents = parseIntegrityRemediationExecutionEvents(
        parsed.executionEvents ?? []);
      const executionLedger = buildIntegrityRemediationExecutionLedger(
        workspace.plan, decisions, executionEvents);
      // Client-submitted evidence IDs cannot establish trusted verification.
      const execution = verifyIntegrityRemediationExecutionEvidence(
        executionLedger, []);
      const executionPage = parsed.executionQuery === undefined ? null :
        queryIntegrityRemediationExecution(execution,
          parseIntegrityRemediationExecutionQuery(parsed.executionQuery));
      const executionAudit = buildIntegrityExecutionReviewAudit(
        execution, executionEvents);
      const executionEvidence = reconcileIntegrityExecutionEvidence(
        workspace.plan, execution, executionAudit,
        executionEvents, state.events);
      const executionEvidencePage = parsed.executionEvidenceQuery === undefined
        ? null : queryIntegrityExecutionEvidence(executionEvidence,
          parseIntegrityExecutionEvidenceQuery(parsed.executionEvidenceQuery));
      const executionControls = evaluateIntegrityExecutionControls(workspace.plan, decisions, executionEvents, execution, executionAudit, new Date().toISOString(), parseIntegrityExecutionControlPolicy(undefined));
      const executionReadiness = evaluateIntegrityExecutionReadiness(workspace.plan, execution, executionControls, executionEvidence, parseIntegrityExecutionReadinessPolicy(parsed.executionReadinessPolicy));
      const executionReadinessPage = parsed.executionReadinessQuery === undefined ? null : queryIntegrityExecutionReadiness(executionReadiness, parseIntegrityExecutionReadinessQuery(parsed.executionReadinessQuery));
      const executionReadinessHistory = parsed.executionReadinessCheckpoints === undefined ? null : buildIntegrityExecutionReadinessHistory(workspace.plan, decisions, executionEvents, state.events, parsed.executionReadinessCheckpoints as string[], parseIntegrityExecutionReadinessPolicy(parsed.executionReadinessPolicy));
      if (parsed.executionReadinessHistoryQuery !== undefined && executionReadinessHistory === null) throw new WorkInputError("INVALID", "Readiness history query requires checkpoints.");
      const executionReadinessHistoryPage = parsed.executionReadinessHistoryQuery === undefined || executionReadinessHistory === null ? null : queryIntegrityExecutionReadinessHistory(executionReadinessHistory, parseIntegrityExecutionReadinessHistoryQuery(parsed.executionReadinessHistoryQuery));
      const executionQueue = prioritizeIntegrityExecutionRemediation(executionReadiness, executionReadinessHistory, new Date().toISOString(), parseIntegrityExecutionRemediationQueuePolicy(parsed.executionQueuePolicy));
      const executionQueuePage = parsed.executionQueueQuery === undefined ? null : queryIntegrityExecutionRemediationQueue(executionQueue, parseIntegrityExecutionRemediationQueueQuery(parsed.executionQueueQuery));
      if (parsed.executionCapacityMembers === undefined && (parsed.executionCapacityPolicy !== undefined || parsed.executionCapacityQuery !== undefined)) throw new WorkInputError("INVALID", "Capacity options require capacity members.");
      const executionCapacity = parsed.executionCapacityMembers === undefined ? null : planIntegrityExecutionCapacity(executionQueue, parseIntegrityExecutionCapacityMembers(parsed.executionCapacityMembers), new Date().toISOString(), parseIntegrityExecutionCapacityPolicy(parsed.executionCapacityPolicy));
      const executionCapacityPage = parsed.executionCapacityQuery === undefined || executionCapacity === null ? null : queryIntegrityExecutionCapacity(executionCapacity, parseIntegrityExecutionCapacityQuery(parsed.executionCapacityQuery));
      if (executionCapacity === null && (parsed.executionCapacityForecastPolicy !== undefined || parsed.executionCapacityForecastQuery !== undefined)) throw new WorkInputError("INVALID", "Forecast requires capacity members.");
      const executionCapacityForecast = executionCapacity === null ? null : forecastIntegrityExecutionCapacity(executionCapacity, executionQueue, new Date().toISOString(), parseIntegrityExecutionCapacityForecastPolicy(parsed.executionCapacityForecastPolicy));
      const executionCapacityForecastPage = parsed.executionCapacityForecastQuery === undefined || executionCapacityForecast === null ? null : queryIntegrityExecutionCapacityForecast(executionCapacityForecast, parseIntegrityExecutionCapacityForecastQuery(parsed.executionCapacityForecastQuery));
      if (parsed.executionCapacityExport !== undefined && executionCapacity === null) throw new WorkInputError("INVALID", "Capacity export requires capacity members.");
      const executionCapacityExport = parsed.executionCapacityExport === undefined || executionCapacity === null ? null : exportIntegrityExecutionCapacity(executionCapacity, executionCapacityForecast, parseIntegrityExecutionCapacityExportOptions(parsed.executionCapacityExport));
      const executionMatrix = buildIntegrityExecutionReviewMatrix(
        execution, workspace.plan);
      const executionReviewPage = parsed.executionReviewQuery === undefined
        ? null : queryIntegrityExecutionReview(executionAudit,
          parseIntegrityExecutionReviewQuery(parsed.executionReviewQuery));
      const executionHistory = parsed.executionCheckpoints === undefined
        ? null : buildIntegrityExecutionReviewHistory(
          workspace.plan, decisions, executionEvents,
          parsed.executionCheckpoints as string[]);
      const executionPerformance = executionHistory === null ? null :
        evaluateIntegrityExecutionPerformance(
          execution, executionHistory, executionAudit,
          executionHistory.summary.lastAt);
      if (parsed.executionPerformanceQuery !== undefined &&
          executionPerformance === null)
        throw new WorkInputError("INVALID", "Execution performance requires checkpoints.");
      const executionPerformancePage =
        parsed.executionPerformanceQuery === undefined ||
        executionPerformance === null ? null :
          queryIntegrityExecutionPerformance(executionPerformance,
            parseIntegrityExecutionPerformanceQuery(
              parsed.executionPerformanceQuery));
      if (parsed.escalationPolicy !== undefined &&
          parsed.slaPolicy === undefined)
        throw new WorkInputError("INVALID", "Escalation policy requires SLA policy.");
      if (parsed.slaPolicy === undefined) {
        if (parsed.createdAt !== undefined || parsed.evaluatedAt !== undefined ||
            parsed.escalationPolicy !== undefined ||
            parsed.acknowledgements !== undefined ||
            parsed.slaQuery !== undefined || parsed.escalationQuery !== undefined)
          throw new WorkInputError("INVALID", "SLA parameters require SLA policy.");
        return NextResponse.json({ workspace, audit, execution, executionPage,
          executionAudit, executionMatrix, executionReviewPage, executionHistory,
          executionPerformance, executionPerformancePage,
          executionEvidence, executionEvidencePage, executionControls, executionReadiness, executionReadinessPage,
          executionReadinessHistory, executionReadinessHistoryPage,
          executionQueue, executionQueuePage,
          executionCapacity, executionCapacityPage,
          executionCapacityForecast, executionCapacityForecastPage,
          executionCapacityExport }, { headers });
      }
      if (typeof parsed.createdAt !== "string" ||
          typeof parsed.evaluatedAt !== "string")
        throw new WorkInputError("INVALID", "SLA timestamps required.");
      const sla = evaluateIntegrityRemediationSla(
        workspace.plan, decisions, parsed.createdAt, parsed.evaluatedAt,
        parseIntegrityRemediationSlaPolicy(parsed.slaPolicy));
      const slaPage = parsed.slaQuery === undefined ? null :
        queryIntegrityRemediationSla(sla,
          parseIntegrityRemediationSlaQuery(parsed.slaQuery));
      if (parsed.escalationPolicy === undefined) {
        if (parsed.acknowledgements !== undefined ||
            parsed.escalationQuery !== undefined)
          throw new WorkInputError("INVALID", "Escalation options require policy.");
        return NextResponse.json({ workspace, audit, sla, slaPage, execution, executionPage,
          executionAudit, executionMatrix, executionReviewPage, executionHistory,
          executionPerformance, executionPerformancePage,
          executionEvidence, executionEvidencePage, executionControls, executionReadiness, executionReadinessPage,
          executionReadinessHistory, executionReadinessHistoryPage,
          executionQueue, executionQueuePage,
          executionCapacity, executionCapacityPage,
          executionCapacityForecast, executionCapacityForecastPage,
          executionCapacityExport }, { headers });
      }
      const escalations = evaluateIntegrityEscalations(
        sla, parseIntegrityEscalationPolicy(parsed.escalationPolicy),
        decisions, parseIntegrityEscalationAcknowledgements(
          parsed.acknowledgements ?? []));
      const escalationPage = parsed.escalationQuery === undefined ? null :
        queryIntegrityEscalations(escalations,
          parseIntegrityEscalationQuery(parsed.escalationQuery));
      const deliveryManifest = buildIntegrityEscalationDeliveryManifest(
        escalations);
      return NextResponse.json({
        workspace, audit, sla, slaPage, execution, executionPage, escalations,
        escalationPage, deliveryManifest,
        executionAudit, executionMatrix, executionReviewPage, executionHistory,
        executionPerformance, executionPerformancePage,
        executionEvidence, executionEvidencePage, executionControls, executionReadiness, executionReadinessPage,
          executionReadinessHistory, executionReadinessHistoryPage,
          executionQueue, executionQueuePage,
          executionCapacity, executionCapacityPage,
          executionCapacityForecast, executionCapacityForecastPage,
          executionCapacityExport,
      }, { headers });
    }
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
