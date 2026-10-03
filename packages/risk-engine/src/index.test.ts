import { describe, expect, it } from "vitest";

import { evaluateM365IdentityFindings } from "./index";

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
