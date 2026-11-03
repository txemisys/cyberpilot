import { parseIntegrityReviewBatchPolicy, evaluateIntegrityReviewBatch, parseIntegrityReviewBatchQuery, queryIntegrityReviewBatch } from "../../../../../../../../../lib/work-integrity-remediation-review-batch";
import { parseIntegrityReviewLineagePolicy, buildIntegrityReviewLineage, parseIntegrityReviewLineageQuery, queryIntegrityReviewLineage } from "../../../../../../../../../lib/work-integrity-remediation-review-lineage";
import { parseIntegrityReviewDossierPolicy, buildIntegrityReviewDossier, parseIntegrityReviewDossierQuery, queryIntegrityReviewDossier } from "../../../../../../../../../lib/work-integrity-remediation-review-dossier";
import { parseIntegrityReviewEvidenceAssociations, reconcileIntegrityReviewEvidence, parseIntegrityReviewEvidenceQuery, queryIntegrityReviewEvidence } from "../../../../../../../../../lib/work-integrity-remediation-review-evidence";
import { parseIntegrityReviewDeadlinePolicy, evaluateIntegrityReviewDeadlines, parseIntegrityReviewDeadlineQuery, queryIntegrityReviewDeadlines } from "../../../../../../../../../lib/work-integrity-remediation-review-deadlines";
import { parseIntegrityReviewEscalationPolicy, buildIntegrityReviewEscalations, parseIntegrityReviewEscalationQuery, queryIntegrityReviewEscalations } from "../../../../../../../../../lib/work-integrity-remediation-review-escalations";
import { parseIntegrityReviewEvents, parseIntegrityReviewReplayPolicy, replayIntegrityReviewEvents, parseIntegrityReviewReplayQuery, queryIntegrityReviewReplay } from "../../../../../../../../../lib/work-integrity-remediation-review-event-replay";
import { evaluateIntegrityReviewGate, parseIntegrityReviewGatePolicy, parseIntegrityReviewGateQuery, queryIntegrityReviewGate } from "../../../../../../../../../lib/work-integrity-remediation-review-gate";
import { parseIntegrityReviewCheckpoints, buildIntegrityReviewCheckpointHistory, parseIntegrityReviewCheckpointQuery, queryIntegrityReviewCheckpointHistory } from "../../../../../../../../../lib/work-integrity-remediation-review-checkpoints";
import { compareIntegrityCapacityDecisionPolicies, parseIntegrityCapacityDecisionComparisonQuery, queryIntegrityCapacityDecisionComparison } from "../../../../../../../../../lib/work-integrity-remediation-capacity-decision-comparison";
import { evaluateIntegrityCapacityGovernance, parseIntegrityCapacityGovernancePolicy, parseIntegrityCapacityGovernanceQuery, queryIntegrityCapacityGovernance } from "../../../../../../../../../lib/work-integrity-remediation-capacity-governance";
import { buildIntegrityCapacityReviewQueue, parseIntegrityCapacityReviewQuery, queryIntegrityCapacityReviewQueue } from "../../../../../../../../../lib/work-integrity-remediation-capacity-review-queue";
import { decideIntegrityCapacityPortfolio, parseIntegrityCapacityDecisionPolicy, parseIntegrityCapacityDecisionQuery, queryIntegrityCapacityDecision, auditIntegrityCapacityDecision } from "../../../../../../../../../lib/work-integrity-remediation-capacity-decision";
import { analyzeIntegrityCapacitySensitivity, parseIntegrityCapacitySensitivityVariations, parseIntegrityCapacitySensitivityQuery, queryIntegrityCapacitySensitivity, parseIntegrityCapacitySensitivityGridPolicy, evaluateIntegrityCapacitySensitivityGrid } from "../../../../../../../../../lib/work-integrity-remediation-capacity-sensitivity";
import { exportIntegrityCapacityDecision, parseIntegrityCapacityDecisionExportOptions } from "../../../../../../../../../lib/work-integrity-remediation-capacity-decision-export";
import { attributeIntegrityCapacityInterventions, parseIntegrityCapacityInterventionAttributionQuery, queryIntegrityCapacityInterventionAttribution } from "../../../../../../../../../lib/work-integrity-remediation-capacity-attribution";
import { simulateIntegrityCapacityInterventions, parseIntegrityCapacityInterventions, parseIntegrityCapacityInterventionQuery, queryIntegrityCapacityInterventions } from "../../../../../../../../../lib/work-integrity-remediation-capacity-interventions";
import { evaluateIntegrityCapacityPortfolio, parseIntegrityCapacityPortfolioPolicy, parseIntegrityCapacityPortfolioQuery, queryIntegrityCapacityPortfolio } from "../../../../../../../../../lib/work-integrity-remediation-capacity-portfolio";
import { buildIntegrityCapacityCoverage, parseIntegrityCapacityCoverageQuery, queryIntegrityCapacityCoverage } from "../../../../../../../../../lib/work-integrity-remediation-capacity-coverage";
import { compareIntegrityCapacityScenarios, parseIntegrityCapacityScenarios, parseIntegrityCapacityScenarioQuery, queryIntegrityCapacityScenarios } from "../../../../../../../../../lib/work-integrity-remediation-capacity-scenarios";
import { diagnoseIntegrityExecutionCapacity, parseIntegrityCapacityBottleneckPolicy, parseIntegrityCapacityBottleneckQuery, queryIntegrityCapacityBottlenecks } from "../../../../../../../../../lib/work-integrity-remediation-capacity-bottlenecks";
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
    "executionCapacityScenarios", "executionCapacityBaselineId", "executionCapacityScenarioQuery",
    "executionCapacityBottleneckPolicy", "executionCapacityBottleneckQuery",
    "executionCapacityCoverageQuery",
    "executionCapacityInterventions", "executionCapacityInterventionQuery",
    "executionCapacityPortfolioPolicy", "executionCapacityPortfolioQuery",
    "executionCapacityAttributionQuery",
    "executionCapacityDecisionPolicy", "executionCapacityDecisionQuery",
    "executionCapacitySensitivityVariations", "executionCapacitySensitivityGrid",
    "executionCapacitySensitivityQuery", "executionCapacityDecisionExport",
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
    executionCapacityScenarios: raw.executionCapacityScenarios,
    executionCapacityBaselineId: raw.executionCapacityBaselineId,
    executionCapacityScenarioQuery: raw.executionCapacityScenarioQuery,
    executionCapacityBottleneckPolicy: raw.executionCapacityBottleneckPolicy,
    executionCapacityBottleneckQuery: raw.executionCapacityBottleneckQuery,
    executionCapacityCoverageQuery: raw.executionCapacityCoverageQuery,
    executionCapacityInterventions: raw.executionCapacityInterventions,
    executionCapacityInterventionQuery: raw.executionCapacityInterventionQuery,
    executionCapacityPortfolioPolicy: raw.executionCapacityPortfolioPolicy,
    executionCapacityPortfolioQuery: raw.executionCapacityPortfolioQuery,
    executionCapacityAttributionQuery: raw.executionCapacityAttributionQuery,
    executionCapacityDecisionPolicy: raw.executionCapacityDecisionPolicy,
    executionCapacityDecisionQuery: raw.executionCapacityDecisionQuery,
    executionCapacitySensitivityVariations: raw.executionCapacitySensitivityVariations,
    executionCapacitySensitivityGrid: raw.executionCapacitySensitivityGrid,
    executionCapacitySensitivityQuery: raw.executionCapacitySensitivityQuery,
    executionCapacityDecisionExport: raw.executionCapacityDecisionExport,
    executionCapacityComparePolicy: raw.executionCapacityComparePolicy,
    executionCapacityComparisonQuery: raw.executionCapacityComparisonQuery,
    executionCapacityGovernancePolicy: raw.executionCapacityGovernancePolicy,
    executionCapacityGovernanceQuery: raw.executionCapacityGovernanceQuery,
    executionCapacityReviewQuery: raw.executionCapacityReviewQuery,
    executionCapacityReviewEvents: raw.executionCapacityReviewEvents,
    executionCapacityReviewReplayPolicy: raw.executionCapacityReviewReplayPolicy,
    executionCapacityReviewReplayQuery: raw.executionCapacityReviewReplayQuery,
    executionCapacityReviewGatePolicy: raw.executionCapacityReviewGatePolicy,
    executionCapacityReviewGateQuery: raw.executionCapacityReviewGateQuery,
    executionCapacityReviewCheckpoints: raw.executionCapacityReviewCheckpoints,
    executionCapacityReviewCheckpointQuery: raw.executionCapacityReviewCheckpointQuery,
    executionCapacityReviewEvidenceAssociations: raw.executionCapacityReviewEvidenceAssociations,
    executionCapacityReviewEvidenceQuery: raw.executionCapacityReviewEvidenceQuery,
    executionCapacityReviewDeadlinePolicy: raw.executionCapacityReviewDeadlinePolicy,
    executionCapacityReviewDeadlineQuery: raw.executionCapacityReviewDeadlineQuery,
    executionCapacityReviewEscalationPolicy: raw.executionCapacityReviewEscalationPolicy,
    executionCapacityReviewEscalationQuery: raw.executionCapacityReviewEscalationQuery,
    executionCapacityReviewBatchPolicy: raw.executionCapacityReviewBatchPolicy,
    executionCapacityReviewBatchQuery: raw.executionCapacityReviewBatchQuery,
    executionCapacityReviewLineagePolicy: raw.executionCapacityReviewLineagePolicy,
    executionCapacityReviewLineageQuery: raw.executionCapacityReviewLineageQuery,
    executionCapacityReviewDossierPolicy: raw.executionCapacityReviewDossierPolicy,
    executionCapacityReviewDossierQuery: raw.executionCapacityReviewDossierQuery,
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
      if (parsed.executionCapacityScenarios === undefined && (parsed.executionCapacityBaselineId !== undefined || parsed.executionCapacityScenarioQuery !== undefined)) throw new WorkInputError("INVALID", "Scenario options require scenarios.");
      if (parsed.executionCapacityBaselineId !== undefined && (typeof parsed.executionCapacityBaselineId !== "string" || !parsed.executionCapacityBaselineId)) throw new WorkInputError("INVALID", "Invalid scenario baseline.");
      const executionCapacityScenarios = parsed.executionCapacityScenarios === undefined ? null : compareIntegrityCapacityScenarios(executionQueue, parseIntegrityCapacityScenarios(parsed.executionCapacityScenarios), new Date().toISOString(), parsed.executionCapacityBaselineId as string | undefined);
      const executionCapacityScenarioPage = parsed.executionCapacityScenarioQuery === undefined || executionCapacityScenarios === null ? null : queryIntegrityCapacityScenarios(executionCapacityScenarios, parseIntegrityCapacityScenarioQuery(parsed.executionCapacityScenarioQuery));
      if (executionCapacity === null && (parsed.executionCapacityBottleneckPolicy !== undefined || parsed.executionCapacityBottleneckQuery !== undefined)) throw new WorkInputError("INVALID", "Bottleneck options require capacity members.");
      const executionCapacityBottlenecks = executionCapacity === null ? null : diagnoseIntegrityExecutionCapacity(executionQueue, executionCapacity, executionCapacityForecast, parseIntegrityCapacityBottleneckPolicy(parsed.executionCapacityBottleneckPolicy));
      const executionCapacityBottleneckPage = parsed.executionCapacityBottleneckQuery === undefined || executionCapacityBottlenecks === null ? null : queryIntegrityCapacityBottlenecks(executionCapacityBottlenecks, parseIntegrityCapacityBottleneckQuery(parsed.executionCapacityBottleneckQuery));
      if (executionCapacity === null && parsed.executionCapacityCoverageQuery !== undefined) throw new WorkInputError("INVALID", "Coverage query requires capacity members.");
      const executionCapacityCoverage = executionCapacity === null ? null : buildIntegrityCapacityCoverage(executionQueue, executionCapacity, executionCapacityForecast);
      const executionCapacityCoveragePage = parsed.executionCapacityCoverageQuery === undefined || executionCapacityCoverage === null ? null : queryIntegrityCapacityCoverage(executionCapacityCoverage, parseIntegrityCapacityCoverageQuery(parsed.executionCapacityCoverageQuery));
      if (parsed.executionCapacityInterventions === undefined && (parsed.executionCapacityInterventionQuery !== undefined || parsed.executionCapacityPortfolioPolicy !== undefined || parsed.executionCapacityPortfolioQuery !== undefined)) throw new WorkInputError("INVALID", "Intervention queries require intervention inputs.");
      if (parsed.executionCapacityInterventions !== undefined && parsed.executionCapacityMembers === undefined) throw new WorkInputError("INVALID", "Interventions require capacity members.");
      const capacityInterventions = parsed.executionCapacityInterventions === undefined ? null : parseIntegrityCapacityInterventions(parsed.executionCapacityInterventions);
      const interventionMembers = capacityInterventions === null ? null : parseIntegrityExecutionCapacityMembers(parsed.executionCapacityMembers);
      const interventionCapacityPolicy = capacityInterventions === null ? null : parseIntegrityExecutionCapacityPolicy(parsed.executionCapacityPolicy);
      const interventionForecastPolicy = capacityInterventions === null ? null : parseIntegrityExecutionCapacityForecastPolicy(parsed.executionCapacityForecastPolicy);
      const executionCapacityInterventions = capacityInterventions === null || interventionMembers === null || interventionCapacityPolicy === null || interventionForecastPolicy === null ? null : simulateIntegrityCapacityInterventions(executionQueue, interventionMembers, new Date().toISOString(), interventionCapacityPolicy, interventionForecastPolicy, capacityInterventions);
      const executionCapacityInterventionPage = parsed.executionCapacityInterventionQuery === undefined || executionCapacityInterventions === null ? null : queryIntegrityCapacityInterventions(executionCapacityInterventions, parseIntegrityCapacityInterventionQuery(parsed.executionCapacityInterventionQuery));
      const executionCapacityPortfolio = capacityInterventions === null || interventionMembers === null || interventionCapacityPolicy === null || interventionForecastPolicy === null || parsed.executionCapacityPortfolioPolicy === undefined ? null : evaluateIntegrityCapacityPortfolio(executionQueue, interventionMembers, new Date().toISOString(), interventionCapacityPolicy, interventionForecastPolicy, capacityInterventions, parseIntegrityCapacityPortfolioPolicy(parsed.executionCapacityPortfolioPolicy));
      const executionCapacityPortfolioPage = parsed.executionCapacityPortfolioQuery === undefined || executionCapacityPortfolio === null ? null : queryIntegrityCapacityPortfolio(executionCapacityPortfolio, parseIntegrityCapacityPortfolioQuery(parsed.executionCapacityPortfolioQuery));
      if (parsed.executionCapacityAttributionQuery !== undefined && (executionCapacityPortfolio === null || executionCapacityInterventions === null)) throw new WorkInputError("INVALID", "Attribution requires intervention portfolio.");
      const executionCapacityAttribution = executionCapacityPortfolio === null || executionCapacityInterventions === null ? null : attributeIntegrityCapacityInterventions(executionCapacityInterventions, executionCapacityPortfolio);
      const executionCapacityAttributionPage = parsed.executionCapacityAttributionQuery === undefined || executionCapacityAttribution === null ? null : queryIntegrityCapacityInterventionAttribution(executionCapacityAttribution, parseIntegrityCapacityInterventionAttributionQuery(parsed.executionCapacityAttributionQuery));
      const decisionInputsPresent = parsed.executionCapacityDecisionPolicy !== undefined || parsed.executionCapacityDecisionQuery !== undefined || parsed.executionCapacitySensitivityVariations !== undefined || parsed.executionCapacitySensitivityGrid !== undefined || parsed.executionCapacitySensitivityQuery !== undefined || parsed.executionCapacityDecisionExport !== undefined || parsed.executionCapacityComparePolicy !== undefined || parsed.executionCapacityComparisonQuery !== undefined || parsed.executionCapacityGovernancePolicy !== undefined || parsed.executionCapacityGovernanceQuery !== undefined || parsed.executionCapacityReviewQuery !== undefined || parsed.executionCapacityReviewEvents !== undefined || parsed.executionCapacityReviewReplayPolicy !== undefined || parsed.executionCapacityReviewReplayQuery !== undefined || parsed.executionCapacityReviewGatePolicy !== undefined || parsed.executionCapacityReviewGateQuery !== undefined || parsed.executionCapacityReviewCheckpoints !== undefined || parsed.executionCapacityReviewCheckpointQuery !== undefined || parsed.executionCapacityReviewEvidenceAssociations !== undefined || parsed.executionCapacityReviewEvidenceQuery !== undefined || parsed.executionCapacityReviewDeadlinePolicy !== undefined || parsed.executionCapacityReviewDeadlineQuery !== undefined || parsed.executionCapacityReviewEscalationPolicy !== undefined || parsed.executionCapacityReviewEscalationQuery !== undefined || parsed.executionCapacityReviewBatchPolicy !== undefined || parsed.executionCapacityReviewBatchQuery !== undefined || parsed.executionCapacityReviewLineagePolicy !== undefined || parsed.executionCapacityReviewLineageQuery !== undefined || parsed.executionCapacityReviewDossierPolicy !== undefined || parsed.executionCapacityReviewDossierQuery !== undefined;
      if (decisionInputsPresent && executionCapacityPortfolio === null) throw new WorkInputError("INVALID", "Capacity decisions require a portfolio.");
      if (parsed.executionCapacitySensitivityVariations !== undefined && parsed.executionCapacitySensitivityGrid !== undefined) throw new WorkInputError("INVALID", "Choose variations or a sensitivity grid.");
      if (parsed.executionCapacitySensitivityQuery !== undefined && parsed.executionCapacitySensitivityVariations === undefined && parsed.executionCapacitySensitivityGrid === undefined) throw new WorkInputError("INVALID", "Sensitivity query requires variations or a grid.");
      const executionCapacityDecisionPolicy = decisionInputsPresent ? parseIntegrityCapacityDecisionPolicy(parsed.executionCapacityDecisionPolicy) : null;
      const executionCapacityDecision = executionCapacityPortfolio === null || executionCapacityDecisionPolicy === null ? null : decideIntegrityCapacityPortfolio(executionCapacityPortfolio, executionCapacityDecisionPolicy);
      const executionCapacityDecisionPage = parsed.executionCapacityDecisionQuery === undefined || executionCapacityDecision === null ? null : queryIntegrityCapacityDecision(executionCapacityDecision, parseIntegrityCapacityDecisionQuery(parsed.executionCapacityDecisionQuery));
      const executionCapacityDecisionAudit = executionCapacityDecision === null || executionCapacityPortfolio === null ? null : auditIntegrityCapacityDecision(executionCapacityDecision, executionCapacityPortfolio, executionCapacityInterventions, executionCapacityAttribution);
      const executionCapacitySensitivity = executionCapacityPortfolio === null || executionCapacityDecisionPolicy === null ? null : parsed.executionCapacitySensitivityVariations !== undefined ? analyzeIntegrityCapacitySensitivity(executionCapacityPortfolio, executionCapacityDecisionPolicy, parseIntegrityCapacitySensitivityVariations(parsed.executionCapacitySensitivityVariations)) : parsed.executionCapacitySensitivityGrid !== undefined ? evaluateIntegrityCapacitySensitivityGrid(executionCapacityPortfolio, executionCapacityDecisionPolicy, parseIntegrityCapacitySensitivityGridPolicy(parsed.executionCapacitySensitivityGrid)) : null;
      const executionCapacitySensitivityPage = parsed.executionCapacitySensitivityQuery === undefined || executionCapacitySensitivity === null ? null : queryIntegrityCapacitySensitivity(executionCapacitySensitivity, parseIntegrityCapacitySensitivityQuery(parsed.executionCapacitySensitivityQuery));
      const executionCapacityDecisionExport = parsed.executionCapacityDecisionExport === undefined || executionCapacityDecision === null ? null : exportIntegrityCapacityDecision(executionCapacityDecision, executionCapacitySensitivity, executionCapacityDecisionAudit, parseIntegrityCapacityDecisionExportOptions(parsed.executionCapacityDecisionExport));
      if (parsed.executionCapacityComparisonQuery !== undefined && parsed.executionCapacityComparePolicy === undefined) throw new WorkInputError("INVALID", "Comparison query requires comparison policy.");
      const executionCapacityComparison = executionCapacityPortfolio === null || executionCapacityDecisionPolicy === null || parsed.executionCapacityComparePolicy === undefined ? null : compareIntegrityCapacityDecisionPolicies(executionCapacityPortfolio, executionCapacityDecisionPolicy, parseIntegrityCapacityDecisionPolicy(parsed.executionCapacityComparePolicy));
      const executionCapacityComparisonPage = parsed.executionCapacityComparisonQuery === undefined || executionCapacityComparison === null ? null : queryIntegrityCapacityDecisionComparison(executionCapacityComparison, parseIntegrityCapacityDecisionComparisonQuery(parsed.executionCapacityComparisonQuery));
      const executionCapacityGovernance = executionCapacityPortfolio === null || executionCapacityDecision === null ? null : evaluateIntegrityCapacityGovernance(executionCapacityPortfolio, executionCapacityDecision, executionCapacitySensitivity, executionCapacityDecisionAudit, executionCapacityComparison, parseIntegrityCapacityGovernancePolicy(parsed.executionCapacityGovernancePolicy));
      const executionCapacityGovernancePage = parsed.executionCapacityGovernanceQuery === undefined || executionCapacityGovernance === null ? null : queryIntegrityCapacityGovernance(executionCapacityGovernance, parseIntegrityCapacityGovernanceQuery(parsed.executionCapacityGovernanceQuery));
      const executionCapacityReviewQueue = executionCapacityGovernance === null || executionCapacityDecision === null || executionCapacityPortfolio === null ? null : buildIntegrityCapacityReviewQueue(executionCapacityGovernance, executionCapacityDecision, executionCapacityPortfolio);
      const executionCapacityReviewPage = parsed.executionCapacityReviewQuery === undefined || executionCapacityReviewQueue === null ? null : queryIntegrityCapacityReviewQueue(executionCapacityReviewQueue, parseIntegrityCapacityReviewQuery(parsed.executionCapacityReviewQuery));
      const reviewReplayRequested = parsed.executionCapacityReviewEvents !== undefined || parsed.executionCapacityReviewReplayPolicy !== undefined || parsed.executionCapacityReviewReplayQuery !== undefined || parsed.executionCapacityReviewGatePolicy !== undefined || parsed.executionCapacityReviewGateQuery !== undefined || parsed.executionCapacityReviewCheckpoints !== undefined || parsed.executionCapacityReviewCheckpointQuery !== undefined;
      if (reviewReplayRequested && parsed.executionCapacityReviewEvents === undefined) throw new WorkInputError("INVALID", "Review replay requires review events.");
      if (parsed.executionCapacityReviewCheckpointQuery !== undefined && parsed.executionCapacityReviewCheckpoints === undefined) throw new WorkInputError("INVALID", "Checkpoint query requires checkpoints.");
      const executionCapacityReviewEvents = parsed.executionCapacityReviewEvents === undefined ? null : parseIntegrityReviewEvents(parsed.executionCapacityReviewEvents);
      const executionCapacityReviewReplayPolicy = reviewReplayRequested ? parseIntegrityReviewReplayPolicy(parsed.executionCapacityReviewReplayPolicy) : null;
      const executionCapacityReviewReplay = executionCapacityReviewQueue === null || executionCapacityReviewEvents === null || executionCapacityReviewReplayPolicy === null ? null : replayIntegrityReviewEvents(executionCapacityReviewQueue, executionCapacityReviewEvents, executionCapacityReviewReplayPolicy);
      const executionCapacityReviewReplayPage = parsed.executionCapacityReviewReplayQuery === undefined || executionCapacityReviewReplay === null ? null : queryIntegrityReviewReplay(executionCapacityReviewReplay, parseIntegrityReviewReplayQuery(parsed.executionCapacityReviewReplayQuery));
      const executionCapacityReviewGate = executionCapacityGovernance === null || executionCapacityDecision === null || executionCapacityReviewQueue === null || executionCapacityReviewReplay === null ? null : evaluateIntegrityReviewGate(executionCapacityGovernance, executionCapacityDecision, executionCapacityReviewQueue, executionCapacityReviewReplay, parseIntegrityReviewGatePolicy(parsed.executionCapacityReviewGatePolicy));
      const executionCapacityReviewGatePage = parsed.executionCapacityReviewGateQuery === undefined || executionCapacityReviewGate === null ? null : queryIntegrityReviewGate(executionCapacityReviewGate, parseIntegrityReviewGateQuery(parsed.executionCapacityReviewGateQuery));
      const executionCapacityReviewHistory = parsed.executionCapacityReviewCheckpoints === undefined || executionCapacityReviewQueue === null || executionCapacityReviewEvents === null || executionCapacityReviewReplayPolicy === null ? null : buildIntegrityReviewCheckpointHistory(executionCapacityReviewQueue, executionCapacityReviewEvents, parseIntegrityReviewCheckpoints(parsed.executionCapacityReviewCheckpoints), executionCapacityReviewReplayPolicy);
      const executionCapacityReviewHistoryPage = parsed.executionCapacityReviewCheckpointQuery === undefined || executionCapacityReviewHistory === null ? null : queryIntegrityReviewCheckpointHistory(executionCapacityReviewHistory, parseIntegrityReviewCheckpointQuery(parsed.executionCapacityReviewCheckpointQuery));
      if (parsed.executionCapacityReviewEvidenceQuery !== undefined && parsed.executionCapacityReviewEvidenceAssociations === undefined) throw new WorkInputError("INVALID", "Review evidence query requires associations.");
      if ((parsed.executionCapacityReviewDeadlineQuery !== undefined || parsed.executionCapacityReviewEscalationPolicy !== undefined || parsed.executionCapacityReviewEscalationQuery !== undefined) && parsed.executionCapacityReviewDeadlinePolicy === undefined) throw new WorkInputError("INVALID", "Deadline and escalation queries require deadline policy.");
      const executionCapacityReviewEvidence = executionCapacityReviewQueue === null || executionCapacityReviewReplay === null || executionCapacityReviewEvents === null || parsed.executionCapacityReviewEvidenceAssociations === undefined ? null : reconcileIntegrityReviewEvidence(executionCapacityReviewQueue, executionCapacityReviewReplay, executionCapacityReviewEvents, parseIntegrityReviewEvidenceAssociations(parsed.executionCapacityReviewEvidenceAssociations));
      const executionCapacityReviewEvidencePage = parsed.executionCapacityReviewEvidenceQuery === undefined || executionCapacityReviewEvidence === null ? null : queryIntegrityReviewEvidence(executionCapacityReviewEvidence, parseIntegrityReviewEvidenceQuery(parsed.executionCapacityReviewEvidenceQuery));
      const executionCapacityReviewDeadlines = executionCapacityReviewQueue === null || executionCapacityReviewReplay === null || executionCapacityReviewEvents === null || parsed.executionCapacityReviewDeadlinePolicy === undefined ? null : evaluateIntegrityReviewDeadlines(executionCapacityReviewQueue, executionCapacityReviewReplay, executionCapacityReviewEvents, parseIntegrityReviewDeadlinePolicy(parsed.executionCapacityReviewDeadlinePolicy, new Date().toISOString()));
      const executionCapacityReviewDeadlinePage = parsed.executionCapacityReviewDeadlineQuery === undefined || executionCapacityReviewDeadlines === null ? null : queryIntegrityReviewDeadlines(executionCapacityReviewDeadlines, parseIntegrityReviewDeadlineQuery(parsed.executionCapacityReviewDeadlineQuery));
      const executionCapacityReviewEscalations = executionCapacityReviewQueue === null || executionCapacityReviewDeadlines === null ? null : buildIntegrityReviewEscalations(executionCapacityReviewQueue, executionCapacityReviewDeadlines, executionCapacityReviewEvidence, executionCapacityReviewGate, parseIntegrityReviewEscalationPolicy(parsed.executionCapacityReviewEscalationPolicy));
      const executionCapacityReviewEscalationPage = parsed.executionCapacityReviewEscalationQuery === undefined || executionCapacityReviewEscalations === null ? null : queryIntegrityReviewEscalations(executionCapacityReviewEscalations, parseIntegrityReviewEscalationQuery(parsed.executionCapacityReviewEscalationQuery));
      const executionCapacityReviewBatch = executionCapacityReviewQueue === null || executionCapacityReviewEvents === null || executionCapacityReviewReplay === null ? null : evaluateIntegrityReviewBatch(executionCapacityReviewQueue, executionCapacityReviewEvents, executionCapacityReviewReplay, executionCapacityReviewEvidence, parseIntegrityReviewBatchPolicy(parsed.executionCapacityReviewBatchPolicy));
      const executionCapacityReviewBatchPage = parsed.executionCapacityReviewBatchQuery === undefined || executionCapacityReviewBatch === null ? null : queryIntegrityReviewBatch(executionCapacityReviewBatch, parseIntegrityReviewBatchQuery(parsed.executionCapacityReviewBatchQuery));
      const executionCapacityReviewLineage = executionCapacityReviewQueue === null || executionCapacityReviewEvents === null || executionCapacityReviewReplay === null ? null : buildIntegrityReviewLineage(executionCapacityReviewQueue, executionCapacityReviewEvents, executionCapacityReviewReplay, executionCapacityReviewEvidence, executionCapacityReviewBatch, parseIntegrityReviewLineagePolicy(parsed.executionCapacityReviewLineagePolicy));
      const executionCapacityReviewLineagePage = parsed.executionCapacityReviewLineageQuery === undefined || executionCapacityReviewLineage === null ? null : queryIntegrityReviewLineage(executionCapacityReviewLineage, parseIntegrityReviewLineageQuery(parsed.executionCapacityReviewLineageQuery));
      const executionCapacityReviewDossier = executionCapacityReviewQueue === null ? null : buildIntegrityReviewDossier(executionCapacityReviewQueue, executionCapacityReviewReplay, executionCapacityReviewGate, executionCapacityReviewEvidence, executionCapacityReviewDeadlines, executionCapacityReviewBatch, executionCapacityReviewLineage, parseIntegrityReviewDossierPolicy(parsed.executionCapacityReviewDossierPolicy));
      const executionCapacityReviewDossierPage = parsed.executionCapacityReviewDossierQuery === undefined || executionCapacityReviewDossier === null ? null : queryIntegrityReviewDossier(executionCapacityReviewDossier, parseIntegrityReviewDossierQuery(parsed.executionCapacityReviewDossierQuery));
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
          executionCapacityExport,
          executionCapacityScenarios, executionCapacityScenarioPage,
          executionCapacityBottlenecks, executionCapacityBottleneckPage,
          executionCapacityCoverage, executionCapacityCoveragePage,
          executionCapacityInterventions, executionCapacityInterventionPage,
          executionCapacityPortfolio, executionCapacityPortfolioPage,
          executionCapacityAttribution, executionCapacityAttributionPage,
          executionCapacityDecision, executionCapacityDecisionPage,
          executionCapacityDecisionAudit, executionCapacitySensitivity,
          executionCapacitySensitivityPage, executionCapacityDecisionExport,
          executionCapacityComparison, executionCapacityComparisonPage,
          executionCapacityGovernance, executionCapacityGovernancePage,
          executionCapacityReviewQueue, executionCapacityReviewPage,
          executionCapacityReviewReplay, executionCapacityReviewReplayPage,
          executionCapacityReviewGate, executionCapacityReviewGatePage,
          executionCapacityReviewHistory, executionCapacityReviewHistoryPage,
          executionCapacityReviewEvidence, executionCapacityReviewEvidencePage,
          executionCapacityReviewDeadlines, executionCapacityReviewDeadlinePage,
          executionCapacityReviewEscalations, executionCapacityReviewEscalationPage,
          executionCapacityReviewBatch, executionCapacityReviewBatchPage,
          executionCapacityReviewLineage, executionCapacityReviewLineagePage,
          executionCapacityReviewDossier, executionCapacityReviewDossierPage }, { headers });
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
          executionCapacityExport,
          executionCapacityScenarios, executionCapacityScenarioPage,
          executionCapacityBottlenecks, executionCapacityBottleneckPage,
          executionCapacityCoverage, executionCapacityCoveragePage,
          executionCapacityInterventions, executionCapacityInterventionPage,
          executionCapacityPortfolio, executionCapacityPortfolioPage,
          executionCapacityAttribution, executionCapacityAttributionPage,
          executionCapacityDecision, executionCapacityDecisionPage,
          executionCapacityDecisionAudit, executionCapacitySensitivity,
          executionCapacitySensitivityPage, executionCapacityDecisionExport,
          executionCapacityComparison, executionCapacityComparisonPage,
          executionCapacityGovernance, executionCapacityGovernancePage,
          executionCapacityReviewQueue, executionCapacityReviewPage,
          executionCapacityReviewReplay, executionCapacityReviewReplayPage,
          executionCapacityReviewGate, executionCapacityReviewGatePage,
          executionCapacityReviewHistory, executionCapacityReviewHistoryPage,
          executionCapacityReviewEvidence, executionCapacityReviewEvidencePage,
          executionCapacityReviewDeadlines, executionCapacityReviewDeadlinePage,
          executionCapacityReviewEscalations, executionCapacityReviewEscalationPage,
          executionCapacityReviewBatch, executionCapacityReviewBatchPage,
          executionCapacityReviewLineage, executionCapacityReviewLineagePage,
          executionCapacityReviewDossier, executionCapacityReviewDossierPage }, { headers });
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
          executionCapacityScenarios, executionCapacityScenarioPage,
          executionCapacityBottlenecks, executionCapacityBottleneckPage,
          executionCapacityCoverage, executionCapacityCoveragePage,
          executionCapacityInterventions, executionCapacityInterventionPage,
          executionCapacityPortfolio, executionCapacityPortfolioPage,
          executionCapacityAttribution, executionCapacityAttributionPage,
          executionCapacityDecision, executionCapacityDecisionPage,
          executionCapacityDecisionAudit, executionCapacitySensitivity,
          executionCapacitySensitivityPage, executionCapacityDecisionExport,
          executionCapacityComparison, executionCapacityComparisonPage,
          executionCapacityGovernance, executionCapacityGovernancePage,
          executionCapacityReviewQueue, executionCapacityReviewPage,
          executionCapacityReviewReplay, executionCapacityReviewReplayPage,
          executionCapacityReviewGate, executionCapacityReviewGatePage,
          executionCapacityReviewHistory, executionCapacityReviewHistoryPage,
          executionCapacityReviewEvidence, executionCapacityReviewEvidencePage,
          executionCapacityReviewDeadlines, executionCapacityReviewDeadlinePage,
          executionCapacityReviewEscalations, executionCapacityReviewEscalationPage,
          executionCapacityReviewBatch, executionCapacityReviewBatchPage,
          executionCapacityReviewLineage, executionCapacityReviewLineagePage,
          executionCapacityReviewDossier, executionCapacityReviewDossierPage,
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
