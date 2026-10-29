import type { ActionPlan, PlannedAction } from "./evidence-action-plan";
/** Pure filters on a single already-scoped action plan, never a cross-tenant search. */
export type ActionFilter = {
  status?: PlannedAction["status"]; priority?: PlannedAction["priority"];
  owner?: string; overdueOnly?: boolean; query?: string; limit?: number; offset?: number;
};
export type ActionFilterResult = { total: number; items: PlannedAction[] };
export function filterActionPlan(plan: ActionPlan, organizationId: string, options: ActionFilter = {}, asOf: string = "2026-10-29"): ActionFilterResult | null {
  if (!organizationId || plan.organizationId !== organizationId || plan.summary.total !== plan.actions.length) return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(asOf) || !Number.isFinite(Date.parse(asOf+"T00:00:00Z"))) return null;
  const offset = options.offset ?? 0, limit = options.limit ?? 100;
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1000) return null;
  const query = options.query?.trim().toLowerCase() ?? "";
  const owner = options.owner?.trim().toLowerCase();
  const matches = plan.actions.filter(item =>
    (options.status === undefined || item.status === options.status) &&
    (options.priority === undefined || item.priority === options.priority) &&
    (owner === undefined || (item.owner ?? "").toLowerCase() === owner) &&
    (!options.overdueOnly || (item.dueDate !== null && item.dueDate < asOf && item.status !== "DONE")) &&
    (!query || [item.id,item.domain,item.controlId,item.scope,item.reason,item.owner ?? "",item.notes ?? ""].some(value => value.toLowerCase().includes(query)))
  );
  return { total:matches.length, items:matches.slice(offset, offset + limit) };
}
