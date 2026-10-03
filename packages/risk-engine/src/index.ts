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
  remediation: string;
  contextMultiplier: number;
  perRuleCap: number;
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

export type DomainSecurityEvidence = {
  name: string;
  isInitial: boolean;
  spfStatus: "UNKNOWN" | "MISSING" | "PRESENT" | "MULTIPLE" | "ERROR";
  dmarcStatus:
    | "UNKNOWN"
    | "MISSING"
    | "MONITORING"
    | "ENFORCING"
    | "INVALID"
    | "ERROR";
  dmarcPolicy?: string | null;
  dkimStatus: "UNKNOWN" | "MISSING" | "PARTIAL" | "PUBLISHED" | "ERROR";
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
    remediation:
      "Reduce permanent Global Administrator assignments and keep only the minimum number required for emergency and operational access.",
    contextMultiplier: 1.3,
    perRuleCap: 30,
  },
  guestGlobalAdmin: {
    id: "M365_GUEST_GLOBAL_ADMIN",
    severity: "CRITICAL",
    title: "Guest user is a Global Administrator",
    description:
      "A guest identity has the Global Administrator role. Microsoft guidance recommends that guests are not assigned highly privileged directory roles.",
    remediation:
      "Remove the Global Administrator assignment from the guest identity and replace it with the least-privileged role required for its legitimate task.",
    contextMultiplier: 1.6,
    perRuleCap: 40,
  },
  globalAdminMfaNotCapable: {
    id: "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
    severity: "CRITICAL",
    title: "Global Administrator is not MFA-capable",
    description:
      "This active Global Administrator does not have an MFA method that Microsoft currently considers capable under the tenant authentication-method policy.",
    remediation:
      "Register and permit a strong MFA method for this Global Administrator, then re-run the CyberPilot Microsoft 365 sync to verify the control.",
    contextMultiplier: 1.6,
    perRuleCap: 40,
  },
  adminMfaNotCapable: {
    id: "M365_ADMIN_MFA_NOT_CAPABLE",
    severity: "HIGH",
    title: "Administrator is not MFA-capable",
    description:
      "This active administrator does not have an MFA method that Microsoft currently considers capable under the tenant authentication-method policy.",
    remediation:
      "Register and permit a strong MFA method for this administrator, then re-run the CyberPilot Microsoft 365 sync to verify the control.",
    contextMultiplier: 1.35,
    perRuleCap: 30,
  },
} as const satisfies Record<string, RiskRuleDefinition>;


export const DOMAIN_RULES = {
  dmarcMissing: {
    id: "DOMAIN_DMARC_MISSING",
    severity: "HIGH",
    title: "DMARC policy is missing",
    description:
      "No DMARC policy record was observed for this verified custom domain.",
    remediation:
      "Publish a DMARC record for the domain, begin with monitored deployment if necessary, review aggregate reports, and progress toward an enforcing policy after legitimate senders are validated.",
    contextMultiplier: 1.2,
    perRuleCap: 30,
  },
  dmarcInvalid: {
    id: "DOMAIN_DMARC_INVALID",
    severity: "HIGH",
    title: "DMARC policy is invalid",
    description:
      "CyberPilot observed a DMARC record state that cannot be interpreted as one valid policy.",
    remediation:
      "Correct the DMARC DNS record so the domain publishes one valid DMARC policy record with a supported p= policy.",
    contextMultiplier: 1.2,
    perRuleCap: 30,
  },
  dmarcMonitoring: {
    id: "DOMAIN_DMARC_MONITORING_ONLY",
    severity: "MEDIUM",
    title: "DMARC is monitoring only",
    description:
      "The domain publishes DMARC with p=none, which requests reporting but does not request quarantine or rejection of messages that fail DMARC.",
    remediation:
      "Review DMARC reports and, once legitimate senders are aligned, move the policy toward p=quarantine or p=reject according to the organization's rollout plan.",
    contextMultiplier: 1.0,
    perRuleCap: 15,
  },
  spfMissing: {
    id: "DOMAIN_SPF_MISSING",
    severity: "MEDIUM",
    title: "SPF record is missing",
    description:
      "No SPF policy record was observed for this verified custom domain.",
    remediation:
      "Publish one SPF record that accurately authorizes legitimate SMTP senders. If the domain never sends mail, consider an explicit no-senders policy.",
    contextMultiplier: 0.9,
    perRuleCap: 15,
  },
  spfMultiple: {
    id: "DOMAIN_SPF_MULTIPLE",
    severity: "HIGH",
    title: "Multiple SPF records are published",
    description:
      "More than one SPF policy record was observed for the same domain.",
    remediation:
      "Consolidate the domain's sender authorization into one SPF record and re-test DNS after propagation.",
    contextMultiplier: 1.1,
    perRuleCap: 20,
  },
  dkimMissing: {
    id: "DOMAIN_M365_DKIM_SELECTORS_MISSING",
    severity: "LOW",
    title: "Microsoft 365 DKIM selectors were not observed",
    description:
      "Neither standard Microsoft 365 DKIM selector CNAME was observed for this verified custom domain. This DNS signal alone does not prove how every outbound mail path is signed.",
    remediation:
      "If Microsoft 365 sends mail for this domain, configure its DKIM signing and publish the selector1 and selector2 CNAME records provided by Microsoft.",
    contextMultiplier: 0.7,
    perRuleCap: 8,
  },
  dkimPartial: {
    id: "DOMAIN_M365_DKIM_SELECTORS_PARTIAL",
    severity: "LOW",
    title: "Microsoft 365 DKIM selectors are incomplete",
    description:
      "Only one of the two standard Microsoft 365 DKIM selector CNAMEs was observed for this verified custom domain.",
    remediation:
      "Verify the Microsoft 365 DKIM configuration and publish both selector CNAME records supplied for the domain.",
    contextMultiplier: 0.8,
    perRuleCap: 8,
  },
} as const satisfies Record<string, RiskRuleDefinition>;

export const M365_RULE_IDS = Object.values(M365_RULES).map((rule) => rule.id);
export const DOMAIN_RULE_IDS = Object.values(DOMAIN_RULES).map(
  (rule) => rule.id,
);

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



export function evaluateDomainSecurityFindings(
  domains: DomainSecurityEvidence[],
): EvaluatedFinding[] {
  const findings: EvaluatedFinding[] = [];

  for (const domain of domains) {
    if (domain.isInitial) {
      continue;
    }

    if (domain.dmarcStatus === "MISSING") {
      findings.push({
        key: `domain:dmarc-missing:${domain.name}`,
        rule: DOMAIN_RULES.dmarcMissing,
        evidence: {
          domain: domain.name,
          dmarcStatus: domain.dmarcStatus,
        },
      });
    } else if (domain.dmarcStatus === "INVALID") {
      findings.push({
        key: `domain:dmarc-invalid:${domain.name}`,
        rule: DOMAIN_RULES.dmarcInvalid,
        evidence: {
          domain: domain.name,
          dmarcStatus: domain.dmarcStatus,
          dmarcPolicy: domain.dmarcPolicy ?? null,
        },
      });
    } else if (domain.dmarcStatus === "MONITORING") {
      findings.push({
        key: `domain:dmarc-monitoring:${domain.name}`,
        rule: DOMAIN_RULES.dmarcMonitoring,
        evidence: {
          domain: domain.name,
          dmarcStatus: domain.dmarcStatus,
          dmarcPolicy: domain.dmarcPolicy ?? null,
        },
      });
    }

    if (domain.spfStatus === "MISSING") {
      findings.push({
        key: `domain:spf-missing:${domain.name}`,
        rule: DOMAIN_RULES.spfMissing,
        evidence: {
          domain: domain.name,
          spfStatus: domain.spfStatus,
        },
      });
    } else if (domain.spfStatus === "MULTIPLE") {
      findings.push({
        key: `domain:spf-multiple:${domain.name}`,
        rule: DOMAIN_RULES.spfMultiple,
        evidence: {
          domain: domain.name,
          spfStatus: domain.spfStatus,
        },
      });
    }

    if (domain.dkimStatus === "MISSING") {
      findings.push({
        key: `domain:m365-dkim-missing:${domain.name}`,
        rule: DOMAIN_RULES.dkimMissing,
        evidence: {
          domain: domain.name,
          dkimStatus: domain.dkimStatus,
        },
      });
    } else if (domain.dkimStatus === "PARTIAL") {
      findings.push({
        key: `domain:m365-dkim-partial:${domain.name}`,
        rule: DOMAIN_RULES.dkimPartial,
        evidence: {
          domain: domain.name,
          dkimStatus: domain.dkimStatus,
        },
      });
    }
  }

  return findings;
}

export type PrioritizableFinding = {
  id: string;
  ruleId: string;
  severity: RiskSeverity;
  title: string;
  description: string;
};

export type PrioritizedFinding = PrioritizableFinding & {
  priorityScore: number;
  riskPoints: number;
  remediation: string;
  rationale: string;
};

export type CyberScoreResult = {
  score: number;
  totalRiskPoints: number;
  supportedFindingCount: number;
  unsupportedFindingCount: number;
  topActions: PrioritizedFinding[];
  contributions: Array<{
    ruleId: string;
    findingCount: number;
    uncappedRiskPoints: number;
    appliedRiskPoints: number;
    cap: number;
  }>;
};

const SEVERITY_POINTS: Record<RiskSeverity, number> = {
  INFO: 1,
  LOW: 3,
  MEDIUM: 7,
  HIGH: 15,
  CRITICAL: 25,
};

const RULES_BY_ID = new Map<string, RiskRuleDefinition>(
  [...Object.values(M365_RULES), ...Object.values(DOMAIN_RULES)].map((rule) => [
    rule.id,
    rule,
  ]),
);

function roundRiskPoints(value: number) {
  return Math.round(value * 10) / 10;
}

export function prioritizeFindings(
  findings: PrioritizableFinding[],
): PrioritizedFinding[] {
  return findings
    .flatMap((finding) => {
      const rule = RULES_BY_ID.get(finding.ruleId);

      if (!rule) {
        return [];
      }

      const riskPoints = roundRiskPoints(
        SEVERITY_POINTS[finding.severity] * rule.contextMultiplier,
      );

      return [
        {
          ...finding,
          priorityScore: riskPoints,
          riskPoints,
          remediation: rule.remediation,
          rationale:
            `${finding.severity} severity × ${rule.contextMultiplier.toFixed(
              2,
            )} context multiplier = ${riskPoints.toFixed(1)} risk points.`,
        },
      ];
    })
    .sort(
      (left, right) =>
        right.priorityScore - left.priorityScore ||
        left.ruleId.localeCompare(right.ruleId) ||
        left.id.localeCompare(right.id),
    );
}

export function calculateCyberScore(
  findings: PrioritizableFinding[],
): CyberScoreResult {
  const supported = prioritizeFindings(findings);
  const contributionsByRule = new Map<
    string,
    {
      findingCount: number;
      uncappedRiskPoints: number;
      appliedRiskPoints: number;
      cap: number;
    }
  >();

  for (const finding of supported) {
    const rule = RULES_BY_ID.get(finding.ruleId);

    if (!rule) {
      continue;
    }

    const current = contributionsByRule.get(finding.ruleId) ?? {
      findingCount: 0,
      uncappedRiskPoints: 0,
      appliedRiskPoints: 0,
      cap: rule.perRuleCap,
    };

    current.findingCount += 1;
    current.uncappedRiskPoints = roundRiskPoints(
      current.uncappedRiskPoints + finding.riskPoints,
    );
    current.appliedRiskPoints = Math.min(
      current.uncappedRiskPoints,
      current.cap,
    );

    contributionsByRule.set(finding.ruleId, current);
  }

  const contributions = [...contributionsByRule.entries()]
    .map(([ruleId, contribution]) => ({
      ruleId,
      ...contribution,
    }))
    .sort(
      (left, right) =>
        right.appliedRiskPoints - left.appliedRiskPoints ||
        left.ruleId.localeCompare(right.ruleId),
    );

  const totalRiskPoints = roundRiskPoints(
    contributions.reduce(
      (total, contribution) => total + contribution.appliedRiskPoints,
      0,
    ),
  );

  return {
    score: Math.max(0, Math.round(100 - totalRiskPoints)),
    totalRiskPoints,
    supportedFindingCount: supported.length,
    unsupportedFindingCount: findings.length - supported.length,
    topActions: supported.slice(0, 3),
    contributions,
  };
}
