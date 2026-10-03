export type RiskSeverity =
  | "INFO"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | { [key: string]: JsonValue };

export type RiskRuleDefinition = {
  id: string;
  severity: RiskSeverity;
  title: string;
  description: string;
};

export type M365IdentityEvidence = {
  externalId: string;
  displayName?: string | null;
  userPrincipalName?: string | null;
  accountEnabled?: boolean | null;
  identityType: "MEMBER" | "GUEST" | "UNKNOWN";
  isAdmin?: boolean | null;
  isMfaRegistered?: boolean | null;
  isMfaCapable?: boolean | null;
  isPasswordlessCapable?: boolean | null;
  methodsRegistered?: string[] | null;
  authenticationObservedAt?: Date | null;
  authenticationUpdatedAt?: Date | null;
};

export type M365RoleDefinitionEvidence = {
  externalId: string;
  templateId?: string | null;
  displayName: string;
};

export type M365RoleAssignmentEvidence = {
  principalExternalId: string;
  roleDefinitionExternalId: string;
};

export type EvaluatedFinding = {
  key: string;
  rule: RiskRuleDefinition;
  evidence: Record<string, JsonValue>;
};

const GLOBAL_ADMIN_TEMPLATE_ID =
  "62e90394-69f5-4237-9190-012177145e10";

export const M365_RULES = {
  globalAdminCountHigh: {
    id: "M365_GLOBAL_ADMIN_COUNT_HIGH",
    severity: "HIGH",
    title: "Too many Global Administrators",
    description:
      "Microsoft recommends assigning the Global Administrator role to fewer than five people.",
  },
  guestGlobalAdmin: {
    id: "M365_GUEST_GLOBAL_ADMIN",
    severity: "CRITICAL",
    title: "Guest user is a Global Administrator",
    description:
      "A guest identity has the Global Administrator role. Microsoft guidance recommends that guests are not assigned highly privileged directory roles.",
  },
  globalAdminMfaNotCapable: {
    id: "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
    severity: "CRITICAL",
    title: "Global Administrator is not MFA-capable",
    description:
      "This active Global Administrator does not have an MFA method that Microsoft currently considers capable under the tenant authentication-method policy.",
  },
  adminMfaNotCapable: {
    id: "M365_ADMIN_MFA_NOT_CAPABLE",
    severity: "HIGH",
    title: "Administrator is not MFA-capable",
    description:
      "This active administrator does not have an MFA method that Microsoft currently considers capable under the tenant authentication-method policy.",
  },
} as const satisfies Record<string, RiskRuleDefinition>;

export const M365_RULE_IDS = Object.values(M365_RULES).map((rule) => rule.id);

export function evaluateM365IdentityFindings(input: {
  identities: M365IdentityEvidence[];
  roleDefinitions: M365RoleDefinitionEvidence[];
  roleAssignments: M365RoleAssignmentEvidence[];
}): EvaluatedFinding[] {
  const identities = new Map(
    input.identities.map((identity) => [identity.externalId, identity]),
  );
  const roles = new Map(
    input.roleDefinitions.map((role) => [role.externalId, role]),
  );

  const globalAdminAssignments = input.roleAssignments.filter(
    (assignment) =>
      roles.get(assignment.roleDefinitionExternalId)?.templateId ===
      GLOBAL_ADMIN_TEMPLATE_ID,
  );

  const activeGlobalAdmins = new Map(
    globalAdminAssignments
      .map((assignment) => identities.get(assignment.principalExternalId))
      .filter(
        (identity): identity is M365IdentityEvidence =>
          Boolean(identity && identity.accountEnabled !== false),
      )
      .map((identity) => [identity.externalId, identity]),
  );

  const findings: EvaluatedFinding[] = [];

  for (const identity of input.identities) {
    if (identity.accountEnabled === false || identity.isMfaCapable !== false) {
      continue;
    }

    const isGlobalAdministrator = activeGlobalAdmins.has(identity.externalId);
    const isAdministrator = identity.isAdmin === true || isGlobalAdministrator;

    if (!isAdministrator) {
      continue;
    }

    const rule = isGlobalAdministrator
      ? M365_RULES.globalAdminMfaNotCapable
      : M365_RULES.adminMfaNotCapable;

    findings.push({
      key: isGlobalAdministrator
        ? `m365:global-admin-mfa-not-capable:${identity.externalId}`
        : `m365:admin-mfa-not-capable:${identity.externalId}`,
      rule,
      evidence: {
        userId: identity.externalId,
        displayName: identity.displayName ?? null,
        userPrincipalName: identity.userPrincipalName ?? null,
        isAdmin: identity.isAdmin ?? null,
        isMfaRegistered: identity.isMfaRegistered ?? null,
        isMfaCapable: identity.isMfaCapable ?? null,
        methodsRegistered: identity.methodsRegistered ?? [],
        authenticationObservedAt:
          identity.authenticationObservedAt?.toISOString() ?? null,
        authenticationUpdatedAt:
          identity.authenticationUpdatedAt?.toISOString() ?? null,
      },
    });
  }

  if (activeGlobalAdmins.size >= 5) {
    findings.push({
      key: "m365:global-admin-count-high",
      rule: M365_RULES.globalAdminCountHigh,
      evidence: {
        activeGlobalAdministratorCount: activeGlobalAdmins.size,
        threshold: 5,
      },
    });
  }

  for (const identity of activeGlobalAdmins.values()) {
    if (identity.identityType !== "GUEST") {
      continue;
    }

    findings.push({
      key: `m365:guest-global-admin:${identity.externalId}`,
      rule: M365_RULES.guestGlobalAdmin,
      evidence: {
        userId: identity.externalId,
        displayName: identity.displayName ?? null,
        userPrincipalName: identity.userPrincipalName ?? null,
      },
    });
  }

  return findings;
}
