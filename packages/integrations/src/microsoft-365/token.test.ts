import { describe, expect, it } from "vitest";

import {
  inspectMicrosoftGraphApplicationRoles,
  MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
} from "./token";

function tokenWithRoles(roles: string[]) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ roles })).toString("base64url");
  return `${header}.${payload}.`;
}

describe("Microsoft Graph application roles", () => {
  it("accepts exactly the first-pilot read-only roles", () => {
    const result = inspectMicrosoftGraphApplicationRoles(
      tokenWithRoles([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
    );

    expect(result.exact).toBe(true);
    expect(result.missing).toEqual([]);
    expect(result.unexpected).toEqual([]);
  });

  it("detects missing and unexpected permissions", () => {
    const result = inspectMicrosoftGraphApplicationRoles(
      tokenWithRoles([
        "Organization.Read.All",
        "User.Read.All",
        "Directory.Read.All",
      ]),
    );

    expect(result.exact).toBe(false);
    expect(result.missing).toEqual(
      expect.arrayContaining([
        "AuditLog.Read.All",
        "RoleManagement.Read.Directory",
      ]),
    );
    expect(result.unexpected).toEqual(["Directory.Read.All"]);
  });

  it("rejects malformed access tokens", () => {
    expect(() => inspectMicrosoftGraphApplicationRoles("opaque-token")).toThrow(
      "Microsoft Graph access token is not a JWT.",
    );
  });
});
