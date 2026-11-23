import { createHash } from "node:crypto";
import { db, type Prisma } from "@cyberpilot/database";
import { collectIntegratedRiskDigest, type IntegratedReviewer } from "./integrated-risk-service";
import { mapCase } from "./evidence-decision-case-service";
import { rowToSnapshot } from "./integrated-action-service";
import { applyDecisionCaseTransition, digestDecisionCase } from "./evidence-decision-case-domain";
import { digestIntegratedActionSnapshot, type ActionPriority } from "./integrated-action-domain";

/**
 * Atomic hand-off of a source-bound evidence case into a human risk action.
 * Neither this service nor the event ledger performs external remediation.
 * A case is never allowed to invent a risk or cross an organization boundary.
 */
export class CaseActionHandoffError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "CaseActionHandoffError";
  }
}
function reject(code: string): never { throw new CaseActionHandoffError(code); }
const identifier = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
const fingerprint = (value: string) => createHash("sha256").update(value).digest("hex");
const iso = (value: unknown): value is string =>
  typeof value === "string" && Number.isFinite(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const priorities = ["LOW", "NORMAL", "HIGH", "URGENT"] as const;
type Priority = (typeof priorities)[number];

export type CaseActionHandoffInput = {
  caseId: string;
  expectedRevision: number;
  riskKey: string;
  priority: ActionPriority;
  ownerUserId: string | null;
  dueAt: string | null;
  rationale: string | null;
};
export type CaseActionHandoffResult = {
  schema: "cyberpilot.case.action.handoff.v1";
  organizationId: string;
  caseId: string;
  actionId: string;
  caseRevision: number;
  actionRevision: number;
  createdAction: boolean;
  linkedCase: boolean;
  idempotentReplay: boolean;
  sourceRiskKey: string;
  originalFindingIds: string[];
  originalEvidenceIds: string[];
  providerWrites: 0;
  independentlyVerifiedRemediation: false;
  customerConsentEstablished: false;
  cyberScoreV1Writes: 0;
};

function validateInput(input: CaseActionHandoffInput) {
  if (!input || !identifier(input.caseId) ||
      !Number.isSafeInteger(input.expectedRevision) ||
      input.expectedRevision < 1 ||
      typeof input.riskKey !== "string" ||
      !/^[a-f0-9]{64}$/.test(input.riskKey) ||
      !priorities.includes(input.priority as Priority) ||
      (input.ownerUserId !== null && !identifier(input.ownerUserId)) ||
      (input.dueAt !== null && (!iso(input.dueAt) || input.dueAt.length > 30)) ||
      (input.rationale !== null && (typeof input.rationale !== "string" ||
        input.rationale.length > 2000 ||
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(input.rationale))))
    reject("CASE_ACTION_INPUT_INVALID");
}
async function validateActor(actor: IntegratedReviewer) {
  if (!identifier(actor.organizationId) || !identifier(actor.userId) ||
      !["OWNER", "ADMIN"].includes(actor.role))
    reject("CASE_ACTION_PERMISSION_REQUIRED");
  const member = await db.membership.findFirst({
    where: { organizationId: actor.organizationId, userId: actor.userId },
    select: { role: true },
  });
  if (!member || member.role !== actor.role)
    reject("CASE_ACTION_MEMBERSHIP_REQUIRED");
}
function storedIds(value: Prisma.JsonValue): string[] {
  if (!Array.isArray(value)) reject("CASE_ACTION_FINDINGS_INVALID");
  if (value.length > 100 || value.some(x => !identifier(x)) ||
      new Set(value).size !== value.length)
    reject("CASE_ACTION_FINDINGS_INVALID");
  return value as string[];
}
function result(input: {
  organizationId: string; caseId: string; actionId: string;
  caseRevision: number; actionRevision: number;
  createdAction: boolean; linkedCase: boolean;
  originalFindingIds: string[]; originalEvidenceIds: string[];
  sourceRiskKey: string;
}): CaseActionHandoffResult {
  return {
    schema: "cyberpilot.case.action.handoff.v1",
    ...input,
    idempotentReplay: !input.linkedCase,
    providerWrites: 0,
    independentlyVerifiedRemediation: false,
    customerConsentEstablished: false,
    cyberScoreV1Writes: 0,
  };
}

/**
 * Recompute the risk from actual organization-scoped evidence.
 * A risk may be related to this case only if a persisted original finding
 * is shared. A matching title, control or untrusted client-provided ID
 * is insufficient. An incomplete source report is never eligible.
 */
export async function handoffDecisionCaseToRiskAction(
  actor: IntegratedReviewer,
  input: CaseActionHandoffInput,
): Promise<CaseActionHandoffResult> {
  await validateActor(actor);
  validateInput(input);
  const registry = await collectIntegratedRiskDigest(actor);
  if (registry.state === "INCOMPLETE")
    reject("CASE_ACTION_RISK_SOURCE_INCOMPLETE");
  const risk = registry.risks.find(x => x.key === input.riskKey);
  if (!risk || risk.status !== "OPEN")
    reject("CASE_ACTION_RISK_NOT_OPEN");
  if (!Array.isArray(risk.sourceFindingIds) ||
      risk.sourceFindingIds.length === 0 ||
      !Array.isArray(risk.sourceEvidenceIds))
    reject("CASE_ACTION_SOURCE_NOT_PROVEN");
  const org = actor.organizationId;
  const now = new Date();

  try {
    return await db.$transaction(async tx => {
      const membership = await tx.membership.findFirst({
        where: { organizationId: org, userId: actor.userId },
        select: { role: true },
      });
      if (!membership || membership.role !== actor.role)
        reject("CASE_ACTION_MEMBERSHIP_REVOKED");
      if (input.ownerUserId !== null) {
        const owner = await tx.membership.findFirst({
          where: { organizationId: org, userId: input.ownerUserId },
          select: { id: true },
        });
        if (!owner) reject("CASE_ACTION_CROSS_TENANT_OWNER");
      }
      const current = await tx.evidenceDecisionCase.findFirst({
        where: { id: input.caseId, organizationId: org },
      });
      if (!current) reject("CASE_ACTION_CASE_NOT_FOUND");
      const findingIds = storedIds(current.findingIds);
      const evidenceIds = storedIds(current.evidenceIds);
      if (!findingIds.length ||
          !risk.sourceFindingIds.some(finding => findingIds.includes(finding)))
        reject("CASE_ACTION_ORIGINAL_FINDING_MISMATCH");
      const originals = await tx.securityFinding.findMany({
        where: { organizationId: org, id: { in: findingIds } },
        select: { id: true },
      });
      if (!originals.some(x => risk.sourceFindingIds.includes(x.id)))
        reject("CASE_ACTION_ORIGINAL_FINDING_NOT_PERSISTED");

      // Replays do not mutate either audit chain, even if the caller's
      // expected revision was that of the original command.
      if (current.relatedActionId) {
        const related = await tx.integratedRiskAction.findFirst({
          where: { id: current.relatedActionId, organizationId: org },
        });
        if (!related || related.riskKey !== input.riskKey)
          reject("CASE_ACTION_DIFFERENT_ACTION_ALREADY_LINKED");
        if (current.revision < input.expectedRevision)
          reject("CASE_ACTION_FUTURE_REVISION");
        return result({
          organizationId: org, caseId: current.id, actionId: related.id,
          caseRevision: current.revision, actionRevision: related.revision,
          createdAction: false, linkedCase: false,
          originalFindingIds: findingIds, originalEvidenceIds: evidenceIds,
          sourceRiskKey: related.riskKey,
        });
      }
      if (current.revision !== input.expectedRevision)
        reject("CASE_ACTION_STALE_CASE_REVISION");

      let action = await tx.integratedRiskAction.findUnique({
        where: { organizationId_riskKey: {
          organizationId: org, riskKey: input.riskKey,
        } },
      });
      let createdAction = false;
      if (!action) {
        action = await tx.integratedRiskAction.create({
          data: {
            organizationId: org,
            riskKey: risk.key,
            title: risk.title.slice(0, 250),
            description: risk.description,
            severity: risk.severity,
            sourceFingerprint: fingerprint(JSON.stringify({
              riskKey: risk.key,
              sourceFindingIds: risk.sourceFindingIds,
              sourceEvidenceIds: risk.sourceEvidenceIds,
            })),
            evidenceRefs: risk.sourceEvidenceIds as Prisma.InputJsonValue,
            status: "OPEN",
            priority: input.priority,
            ownerUserId: input.ownerUserId,
            dueAt: input.dueAt ? new Date(input.dueAt) : null,
            rationale: input.rationale,
            revision: 1,
            createdById: actor.userId,
            updatedById: actor.userId,
            updatedAt: now,
          },
        });
        createdAction = true;
        await tx.integratedRiskActionEvent.create({
          data: {
            organizationId: org,
            actionId: action.id,
            revision: 1,
            kind: "CREATE",
            previousStatus: "OPEN",
            nextStatus: "OPEN",
            actorUserId: actor.userId,
            occurredAt: now,
            snapshot: {
              snapshotDigest: digestIntegratedActionSnapshot(rowToSnapshot(action)),
            } as Prisma.InputJsonValue,
          },
        });
      }
      const transition = applyDecisionCaseTransition(mapCase(current), {
        organizationId: org,
        caseId: current.id,
        actorUserId: actor.userId,
        expectedRevision: current.revision,
        at: now.toISOString(),
        kind: "LINK_ACTION",
        relatedActionId: action.id,
      });
      if (!transition.accepted || !transition.next || !transition.event)
        reject("CASE_ACTION_LINK_REJECTED_" + transition.reason);
      const next = transition.next;
      const changed = await tx.evidenceDecisionCase.updateMany({
        where: {
          id: current.id,
          organizationId: org,
          revision: input.expectedRevision,
          relatedActionId: null,
        },
        data: {
          relatedActionId: action.id,
          revision: next.revision,
          updatedById: actor.userId,
          updatedAt: now,
        },
      });
      if (changed.count !== 1)
        reject("CASE_ACTION_CONCURRENT_LINK_CONFLICT");
      await tx.evidenceDecisionCaseEvent.create({
        data: {
          organizationId: org,
          caseId: current.id,
          revision: next.revision,
          kind: "LINK_ACTION",
          previousStatus: current.status,
          nextStatus: next.status,
          actorUserId: actor.userId,
          occurredAt: now,
          snapshotDigest: digestDecisionCase(next),
        },
      });
      return result({
        organizationId: org,
        caseId: current.id,
        actionId: action.id,
        caseRevision: next.revision,
        actionRevision: action.revision,
        createdAction,
        linkedCase: true,
        originalFindingIds: findingIds,
        originalEvidenceIds: evidenceIds,
        sourceRiskKey: action.riskKey,
      });
    }, { isolationLevel: "Serializable" });
  } catch (error) {
    if (error instanceof CaseActionHandoffError) throw error;
    if (error && typeof error === "object" && "code" in error) {
      if (error.code === "P2034")
        reject("CASE_ACTION_SERIALIZATION_CONFLICT_RETRY");
      if (error.code === "P2002")
        reject("CASE_ACTION_UNIQUE_CONFLICT_RETRY");
    }
    throw error;
  }
}
