import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { MicrosoftGraphClient } from "./client";
import { MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES } from "./token";

function accessToken(roles: string[]) {
  const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ roles })).toString("base64url");
  return `${header}.${payload}.`;
}

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
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
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

    expect(result.applicationPermissions).toEqual({
      status: "EXACT",
      missing: [],
      unexpected: [],
    });
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
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
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

    expect(result.applicationPermissions.status).toBe("EXACT");
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


describe("MicrosoftGraphClient resilience", () => {
  beforeEach(() => {
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
  });

  it("follows Microsoft Graph pagination across @odata.nextLink pages", async () => {
    let usersPage = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("/users?") && usersPage === 0) {
          usersPage += 1;
          return new Response(
            JSON.stringify({
              value: [{ id: "user-1" }],
              "@odata.nextLink":
                "https://graph.microsoft.com/v1.0/users?$skiptoken=page2",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        if (url.includes("$skiptoken=page2")) {
          return new Response(JSON.stringify({ value: [{ id: "user-2" }] }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }

        throw new Error(`Unexpected request: ${url}`);
      }),
    );

    const client = new MicrosoftGraphClient(
      "11111111-1111-1111-1111-111111111111",
    );

    const users = await client.listUsers();

    expect(users.map((user) => user.id)).toEqual(["user-1", "user-2"]);
  });

  it("rejects pagination links outside Microsoft Graph", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        return new Response(
          JSON.stringify({
            value: [{ id: "user-1" }],
            "@odata.nextLink": "https://attacker.example/users?page=2",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const client = new MicrosoftGraphClient(
      "11111111-1111-1111-1111-111111111111",
    );

    await expect(client.listUsers()).rejects.toThrow(
      "Refusing to request an unexpected Microsoft Graph URL.",
    );
  });

  it("retries 429 using Retry-After and then succeeds", async () => {
    let graphCalls = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        graphCalls += 1;

        if (graphCalls === 1) {
          return new Response(JSON.stringify({ error: { code: "TooManyRequests" } }), {
            status: 429,
            headers: { "retry-after": "0", "content-type": "application/json" },
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

    await expect(client.listUsers()).resolves.toEqual([]);
    expect(graphCalls).toBe(2);
  });

  it("retries transient 503 responses but stops after the bounded attempts", async () => {
    let graphCalls = 0;

    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES]),
              expires_in: 3600,
              token_type: "Bearer",
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }

        graphCalls += 1;
        return new Response(JSON.stringify({ error: { code: "ServiceUnavailable" } }), {
          status: 503,
          headers: { "retry-after": "0", "content-type": "application/json" },
        });
      }),
    );

    const client = new MicrosoftGraphClient(
      "11111111-1111-1111-1111-111111111111",
    );

    await expect(client.listUsers()).rejects.toMatchObject({
      name: "MicrosoftGraphError",
      status: 503,
    });
    expect(graphCalls).toBe(3);
  });

  it("marks unexpected application roles as a probe mismatch", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);

        if (url.includes("login.microsoftonline.com")) {
          return new Response(
            JSON.stringify({
              access_token: accessToken([
                ...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
                "Directory.ReadWrite.All",
              ]),
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

    expect(result.applicationPermissions).toMatchObject({
      status: "MISMATCH",
      missing: [],
      unexpected: ["Directory.ReadWrite.All"],
    });
  });
});
