import type { ActionPageInput } from "./action-pagination";

/**
 * Shared database selection for the action center and its CSV export.
 * The supplied organizationId is always mandatory; URL parameters can only narrow scope.
 */
export function buildScopedActionQuery(organizationId:string,settings:ActionPageInput) {
  if(!organizationId)throw new Error("Organization context is required");
  const statusFilter=settings.status==="active"?["EXECUTING"] as const:
    settings.status==="verified"?["VERIFIED"] as const:
    settings.status==="attention"?["PROPOSED","APPROVED","FAILED","SUCCEEDED"] as const:null;
  const where={
    organizationId,
    ...(statusFilter?{status:{in:[...statusFilter]}}:{}),
    ...(settings.severity!=="ALL"?{finding:{severity:settings.severity}}:{}),
    ...(settings.search?{OR:[
      {title:{contains:settings.search,mode:"insensitive" as const}},
      {summary:{contains:settings.search,mode:"insensitive" as const}},
      {finding:{title:{contains:settings.search,mode:"insensitive" as const}}},
    ]}:{}),
  };
  const orderBy=settings.sort==="severity"
    ? [{finding:{severity:"desc" as const}},{createdAt:"desc" as const},{id:"asc" as const}]
    :settings.sort==="oldest"
      ? [{createdAt:"asc" as const},{id:"asc" as const}]
      :[{createdAt:"desc" as const},{id:"asc" as const}];
  return {where,orderBy};
}
