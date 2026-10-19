import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  acquireMicrosoftGraphToken,
  inspectMicrosoftGraphApplicationRoles,
  MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
  MicrosoftGraphTokenError,
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


describe("Microsoft Graph token transport bounds", () => {
  beforeEach(() => {
    process.env.M365_GRAPH_CLIENT_ID = "scanner-client";
    process.env.M365_GRAPH_CLIENT_SECRET = "scanner-secret";
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.M365_GRAPH_CLIENT_ID;
    delete process.env.M365_GRAPH_CLIENT_SECRET;
  });

  it("times out token acquisition instead of waiting indefinitely", async () => {
    const fetcher = vi.fn(
      async (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;

          if (!(signal instanceof AbortSignal)) {
            reject(new Error("Missing abort signal."));
            return;
          }

          signal.addEventListener(
            "abort",
            () => reject(signal.reason),
            { once: true },
          );
        }),
    );

    await expect(
      acquireMicrosoftGraphToken(
        "11111111-1111-1111-1111-111111111111",
        {
          fetcher,
          timeoutMs: 5,
        },
      ),
    ).rejects.toMatchObject({
      name: "MicrosoftGraphTokenError",
      kind: "UNAVAILABLE",
    });
  });

  it("classifies token authorization failures without exposing response bodies", async () => {
    const fetcher = vi.fn(async () =>
      new Response("sensitive upstream body", { status: 401 }),
    );

    await expect(
      acquireMicrosoftGraphToken(
        "11111111-1111-1111-1111-111111111111",
        { fetcher },
      ),
    ).rejects.toMatchObject({
      name: "MicrosoftGraphTokenError",
      kind: "AUTHORIZATION",
      status: 401,
    });
  });
});
