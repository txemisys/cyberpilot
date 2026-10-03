import { describe, expect, it } from "vitest";

import {
  calculateCyberScore,
  evaluateDomainSecurityFindings,
  evaluateM365IdentityFindings,
  getRemediationPlaybook,
  prioritizeFindings,
} from "./index";

const globalAdminRole = {
  externalId: "role-global-admin",
  templateId: "62e90394-69f5-4237-9190-012177145e10",
  displayName: "Global Administrator",
};

function identity(
  overrides: Partial<Parameters<typeof evaluateM365IdentityFindings>[0]["identities"][number]> = {},
) {
  return {
    externalId: "user-1",
    accountEnabled: true,
    identityType: "MEMBER" as const,
    isAdmin: false,
    isMfaCapable: true,
    ...overrides,
  };
}

describe("evaluateM365IdentityFindings", () => {
  it("does not infer MFA risk when evidence is unknown", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          isAdmin: true,
          isMfaCapable: null,
        }),
      ],
      roleDefinitions: [],
      roleAssignments: [],
    });

    expect(findings).toEqual([]);
  });

  it("flags an active administrator explicitly not MFA-capable", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          isAdmin: true,
          isMfaCapable: false,
        }),
      ],
      roleDefinitions: [],
      roleAssignments: [],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule.id).toBe("M365_ADMIN_MFA_NOT_CAPABLE");
    expect(findings[0]?.rule.severity).toBe("HIGH");
  });

  it("does not flag a disabled administrator for MFA capability", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          accountEnabled: false,
          isAdmin: true,
          isMfaCapable: false,
        }),
      ],
      roleDefinitions: [],
      roleAssignments: [],
    });

    expect(findings).toEqual([]);
  });

  it("elevates an active Global Administrator without MFA capability", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          isMfaCapable: false,
        }),
      ],
      roleDefinitions: [globalAdminRole],
      roleAssignments: [
        {
          externalId: "assignment-1",
          principalExternalId: "user-1",
          roleDefinitionExternalId: "role-global-admin",
        },
      ],
    });

    expect(findings.map((finding) => finding.rule.id)).toContain(
      "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
    );
  });

  it("flags an active guest Global Administrator", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          identityType: "GUEST",
        }),
      ],
      roleDefinitions: [globalAdminRole],
      roleAssignments: [
        {
          principalExternalId: "user-1",
          roleDefinitionExternalId: "role-global-admin",
        },
      ],
    });

    expect(findings.map((finding) => finding.rule.id)).toContain(
      "M365_GUEST_GLOBAL_ADMIN",
    );
  });

  it("does not flag four active Global Administrators for count", () => {
    const identities = Array.from({ length: 4 }, (_, index) =>
      identity({
        externalId: `user-${index + 1}`,
      }),
    );

    const findings = evaluateM365IdentityFindings({
      identities,
      roleDefinitions: [globalAdminRole],
      roleAssignments: identities.map((user) => ({
        principalExternalId: user.externalId,
        roleDefinitionExternalId: "role-global-admin",
      })),
    });

    expect(findings.map((finding) => finding.rule.id)).not.toContain(
      "M365_GLOBAL_ADMIN_COUNT_HIGH",
    );
  });

  it("flags five active Global Administrators", () => {
    const identities = Array.from({ length: 5 }, (_, index) =>
      identity({
        externalId: `user-${index + 1}`,
      }),
    );

    const findings = evaluateM365IdentityFindings({
      identities,
      roleDefinitions: [globalAdminRole],
      roleAssignments: identities.map((user) => ({
        principalExternalId: user.externalId,
        roleDefinitionExternalId: "role-global-admin",
      })),
    });

    expect(findings.map((finding) => finding.rule.id)).toContain(
      "M365_GLOBAL_ADMIN_COUNT_HIGH",
    );
  });
});


describe("prioritizeFindings", () => {
  it("prioritizes critical privileged findings above high findings", () => {
    const prioritized = prioritizeFindings([
      {
        id: "high",
        ruleId: "M365_ADMIN_MFA_NOT_CAPABLE",
        severity: "HIGH",
        title: "Admin MFA",
        description: "High",
      },
      {
        id: "critical",
        ruleId: "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
        severity: "CRITICAL",
        title: "Global Admin MFA",
        description: "Critical",
      },
    ]);

    expect(prioritized.map((finding) => finding.id)).toEqual([
      "critical",
      "high",
    ]);
    expect(prioritized[0]?.remediation.length).toBeGreaterThan(0);
    expect(prioritized[0]?.rationale).toContain("risk points");
  });

  it("ignores unsupported findings instead of inventing scoring metadata", () => {
    const prioritized = prioritizeFindings([
      {
        id: "unknown",
        ruleId: "FUTURE_RULE",
        severity: "HIGH",
        title: "Future",
        description: "Not in the current registry",
      },
    ]);

    expect(prioritized).toEqual([]);
  });
});

describe("calculateCyberScore", () => {
  it("starts from 100 and deducts transparent risk contributions", () => {
    const result = calculateCyberScore([
      {
        id: "global-admin-mfa",
        ruleId: "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
        severity: "CRITICAL",
        title: "Global Admin MFA",
        description: "Critical",
      },
    ]);

    expect(result.score).toBe(60);
    expect(result.totalRiskPoints).toBe(40);
    expect(result.supportedFindingCount).toBe(1);
    expect(result.unsupportedFindingCount).toBe(0);
  });

  it("caps repeated findings from the same rule", () => {
    const result = calculateCyberScore(
      Array.from({ length: 5 }, (_, index) => ({
        id: `admin-${index}`,
        ruleId: "M365_ADMIN_MFA_NOT_CAPABLE",
        severity: "HIGH" as const,
        title: "Admin MFA",
        description: "High",
      })),
    );

    const contribution = result.contributions.find(
      (item) => item.ruleId === "M365_ADMIN_MFA_NOT_CAPABLE",
    );

    expect(contribution?.findingCount).toBe(5);
    expect(contribution?.uncappedRiskPoints).toBeGreaterThan(30);
    expect(contribution?.appliedRiskPoints).toBe(30);
    expect(result.score).toBe(70);
  });

  it("returns at most three recommended actions", () => {
    const result = calculateCyberScore([
      {
        id: "one",
        ruleId: "M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE",
        severity: "CRITICAL",
        title: "One",
        description: "One",
      },
      {
        id: "two",
        ruleId: "M365_GUEST_GLOBAL_ADMIN",
        severity: "CRITICAL",
        title: "Two",
        description: "Two",
      },
      {
        id: "three",
        ruleId: "M365_ADMIN_MFA_NOT_CAPABLE",
        severity: "HIGH",
        title: "Three",
        description: "Three",
      },
      {
        id: "four",
        ruleId: "M365_GLOBAL_ADMIN_COUNT_HIGH",
        severity: "HIGH",
        title: "Four",
        description: "Four",
      },
    ]);

    expect(result.topActions).toHaveLength(3);
    expect(result.topActions[0]?.priorityScore).toBeGreaterThanOrEqual(
      result.topActions[1]?.priorityScore ?? 0,
    );
  });

  it("reports unsupported findings separately from the score", () => {
    const result = calculateCyberScore([
      {
        id: "unsupported",
        ruleId: "FUTURE_RULE",
        severity: "CRITICAL",
        title: "Future",
        description: "Unsupported",
      },
    ]);

    expect(result.score).toBe(100);
    expect(result.supportedFindingCount).toBe(0);
    expect(result.unsupportedFindingCount).toBe(1);
  });
});


describe("evaluateDomainSecurityFindings", () => {
  it("skips the Microsoft initial domain", () => {
    const findings = evaluateDomainSecurityFindings([
      {
        name: "tenant.onmicrosoft.com",
        isInitial: true,
        spfStatus: "MISSING",
        dmarcStatus: "MISSING",
        dkimStatus: "MISSING",
      },
    ]);

    expect(findings).toEqual([]);
  });

  it("flags missing DMARC and SPF on a custom domain", () => {
    const findings = evaluateDomainSecurityFindings([
      {
        name: "example.com",
        isInitial: false,
        spfStatus: "MISSING",
        dmarcStatus: "MISSING",
        dkimStatus: "PUBLISHED",
      },
    ]);

    expect(findings.map((finding) => finding.rule.id)).toEqual(
      expect.arrayContaining(["DOMAIN_DMARC_MISSING", "DOMAIN_SPF_MISSING"]),
    );
  });

  it("flags DMARC monitoring without calling it invalid", () => {
    const findings = evaluateDomainSecurityFindings([
      {
        name: "example.com",
        isInitial: false,
        spfStatus: "PRESENT",
        dmarcStatus: "MONITORING",
        dmarcPolicy: "none",
        dkimStatus: "PUBLISHED",
      },
    ]);

    expect(findings.map((finding) => finding.rule.id)).toContain(
      "DOMAIN_DMARC_MONITORING_ONLY",
    );
    expect(findings.map((finding) => finding.rule.id)).not.toContain(
      "DOMAIN_DMARC_INVALID",
    );
  });

  it("adds low-severity DKIM evidence findings without claiming signing state", () => {
    const findings = evaluateDomainSecurityFindings([
      {
        name: "example.com",
        isInitial: false,
        spfStatus: "PRESENT",
        dmarcStatus: "ENFORCING",
        dmarcPolicy: "reject",
        dkimStatus: "MISSING",
      },
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0]?.rule.id).toBe("DOMAIN_M365_DKIM_SELECTORS_MISSING");
    expect(findings[0]?.rule.severity).toBe("LOW");
  });
});


describe("remediation playbooks", () => {
  it("exposes a guided playbook for administrator MFA remediation", () => {
    const playbook = getRemediationPlaybook("M365_ADMIN_MFA_NOT_CAPABLE");

    expect(playbook).not.toBeNull();
    expect(playbook?.mode).toBe("GUIDED");
    expect(playbook?.steps.length).toBeGreaterThan(0);
    expect(playbook?.verification.length).toBeGreaterThan(0);
  });

  it("exposes an automated playbook only for the exact guest role assignment action", () => {
    const playbook = getRemediationPlaybook("M365_GUEST_GLOBAL_ADMIN");

    expect(playbook?.mode).toBe("AUTOMATED");
    expect(playbook?.actionType).toBe(
      "M365_DELETE_DIRECTORY_ROLE_ASSIGNMENT",
    );
  });

  it("retains exact role-assignment evidence for guest Global Administrator remediation", () => {
    const findings = evaluateM365IdentityFindings({
      identities: [
        identity({
          identityType: "GUEST",
        }),
      ],
      roleDefinitions: [globalAdminRole],
      roleAssignments: [
        {
          externalId: "assignment-exact",
          principalExternalId: "user-1",
          roleDefinitionExternalId: "role-global-admin",
        },
      ],
    });

    const finding = findings.find(
      (candidate) => candidate.rule.id === "M365_GUEST_GLOBAL_ADMIN",
    );

    expect(finding?.evidence.roleAssignmentId).toBe("assignment-exact");
    expect(finding?.evidence.roleDefinitionId).toBe("role-global-admin");
  });
});
