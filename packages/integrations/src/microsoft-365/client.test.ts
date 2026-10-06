import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MicrosoftGraphClient } from "./client";

describe("MicrosoftGraphClient read-only readiness probe", () => {
  beforeEach(() => {
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
  });

  it("reports every read-only scope as available when Graph allows all GET probes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: "test-token",
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/organization?")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: "11111111-1111-1111-1111-111111111111",
                  displayName: "Probe Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        return new Response(JSON.stringify({ value: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const client = new MicrosoftGraphClient(
      "11111111-1111-1111-1111-111111111111",
    );

    const result = await client.probeReadOnlyAccess();

    expect(result.checks).toEqual({
      organization: { status: "AVAILABLE" },
      users: { status: "AVAILABLE" },
      roleDefinitions: { status: "AVAILABLE" },
      roleAssignments: { status: "AVAILABLE" },
      authenticationRegistration: { status: "AVAILABLE" },
    });
  });

  it("isolates a missing AuditLog permission without hiding healthy directory access", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: "test-token",
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/organization?")) {
          return new Response(
            JSON.stringify({
              value: [
                {
                  id: "11111111-1111-1111-1111-111111111111",
                  displayName: "Probe Tenant",
                  verifiedDomains: [],
                },
              ],
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/reports/authenticationMethods/userRegistrationDetails")) {
          return new Response(JSON.stringify({ error: { code: "Forbidden" } }), {
            status: 403,
            headers: { "content-type": "application/json" },
          });
        }

        return new Response(JSON.stringify({ value: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }),
    );

    const client = new MicrosoftGraphClient(
      "11111111-1111-1111-1111-111111111111",
    );

    const result = await client.probeReadOnlyAccess();

    expect(result.checks.organization.status).toBe("AVAILABLE");
    expect(result.checks.users.status).toBe("AVAILABLE");
    expect(result.checks.roleDefinitions.status).toBe("AVAILABLE");
    expect(result.checks.roleAssignments.status).toBe("AVAILABLE");
    expect(result.checks.authenticationRegistration).toEqual({
      status: "PERMISSION_REQUIRED",
      httpStatus: 403,
    });
  });
});
