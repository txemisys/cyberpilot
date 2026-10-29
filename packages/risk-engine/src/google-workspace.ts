/** Offline Google Workspace evidence contract (no OAuth, API calls or tenant connection). */
export const GOOGLE_WORKSPACE_SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.group.readonly",
  "https://www.googleapis.com/auth/admin.directory.domain.readonly",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
] as const;
export type WorkspaceUser = { id: string; primaryEmail: string; suspended?: boolean | null; isAdmin?: boolean | null; isEnrolledIn2Sv?: boolean | null; orgUnitPath?: string | null };
export type WorkspaceGroup = { id: string; email: string; directMembersCount?: number | null };
export type WorkspaceDomain = { domainName: string; verified?: boolean | null; isPrimary?: boolean | null };
export type WorkspaceInventory = { organizationId: string; collectedAt: string | null; users: readonly WorkspaceUser[] | null; groups: readonly WorkspaceGroup[] | null; domains: readonly WorkspaceDomain[] | null };
export type WorkspaceCoverage = "UNKNOWN" | "PARTIAL" | "COMPLETE";
export type WorkspaceAssessment = {
  organizationId: string; source: "GOOGLE_WORKSPACE"; state: "OBSERVED" | "UNKNOWN" | "INVALID";
  coverage: WorkspaceCoverage;
  users: { total: number | null; suspended: number | null; admins: number | null; admin2SvNotEnrolled: number | null; unknown2Sv: number | null };
  groups: { total: number | null; empty: number | null };
  domains: { total: number | null; unverified: number | null; primary: number | null };
  warnings: string[];
};
export function assessWorkspaceInventory(inventory: WorkspaceInventory, expectedOrganizationId: string): WorkspaceAssessment {
  const unknown = (state: WorkspaceAssessment["state"]): WorkspaceAssessment => ({
    organizationId: expectedOrganizationId, source: "GOOGLE_WORKSPACE", state, coverage: "UNKNOWN",
    users: {total:null,suspended:null,admins:null,admin2SvNotEnrolled:null,unknown2Sv:null},
    groups: {total:null,empty:null}, domains: {total:null,unverified:null,primary:null}, warnings:[],
  });
  if (!expectedOrganizationId || inventory.organizationId !== expectedOrganizationId) return unknown("INVALID");
  if (!inventory.collectedAt || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(inventory.collectedAt) || !Number.isFinite(Date.parse(inventory.collectedAt))) return unknown("UNKNOWN");
  const users = inventory.users;
  const groups = inventory.groups;
  const domains = inventory.domains;
  const warnings: string[] = [];
  if (users) {
    if (new Set(users.map(x=>x.id)).size !== users.length) warnings.push("DUPLICATE_USER_ID");
    if (users.some(x=>!x.id.trim() || !x.primaryEmail.includes("@"))) warnings.push("INVALID_USER_RECORD");
  }
  if (groups) {
    if (new Set(groups.map(x=>x.id)).size !== groups.length) warnings.push("DUPLICATE_GROUP_ID");
    if (groups.some(x=>x.directMembersCount != null && (!Number.isInteger(x.directMembersCount) || x.directMembersCount < 0))) warnings.push("INVALID_GROUP_MEMBERS");
  }
  if (domains) {
    if (new Set(domains.map(x=>x.domainName.toLowerCase())).size !== domains.length) warnings.push("DUPLICATE_DOMAIN");
    if (domains.filter(x=>x.isPrimary===true).length>1) warnings.push("MULTIPLE_PRIMARY_DOMAINS");
  }
  const sources = [users,groups,domains];
  const coverage: WorkspaceCoverage = sources.every(x=>x!==null)?"COMPLETE":sources.some(x=>x!==null)?"PARTIAL":"UNKNOWN";
  return {
    organizationId:expectedOrganizationId,source:"GOOGLE_WORKSPACE",
    state:warnings.length?"INVALID":coverage==="UNKNOWN"?"UNKNOWN":"OBSERVED",coverage,
    users:{
      total:users?.length ?? null,
      suspended:users?.filter(x=>x.suspended===true).length ?? null,
      admins:users?.filter(x=>x.isAdmin===true).length ?? null,
      admin2SvNotEnrolled:users?.filter(x=>x.isAdmin===true && x.isEnrolledIn2Sv===false).length ?? null,
      unknown2Sv:users?.filter(x=>x.isEnrolledIn2Sv==null).length ?? null,
    },
    groups:{total:groups?.length ?? null,empty:groups?.filter(x=>x.directMembersCount===0).length ?? null},
    domains:{total:domains?.length ?? null,unverified:domains?.filter(x=>x.verified===false).length ?? null,primary:domains?.filter(x=>x.isPrimary===true).length ?? null},
    warnings,
  };
}
