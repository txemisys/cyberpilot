import { describe, expect, it } from "vitest";

import { validateFirstLivePilotConfiguration } from "./first-live-preflight";

const validEnv: NodeJS.ProcessEnv = {
  NODE_ENV: "test",
  BETTER_AUTH_URL: "https://pilot.cyberpilot.example",
  LAB_AUTH_ENABLED: "false",
  MICROSOFT_CLIENT_ID: "login-client",
  M365_GRAPH_CLIENT_ID: "scanner-client",
  M365_GRAPH_CLIENT_SECRET: "scanner-secret",
  M365_GRAPH_REDIRECT_URI:
    "https://pilot.cyberpilot.example/api/integrations/microsoft-365/callback",
};

describe("first LIVE pilot configuration", () => {
  it("accepts a separated read-only scanner on the public HTTPS origin", () => {
    expect(validateFirstLivePilotConfiguration(validEnv)).toEqual({
      ok: true,
      errors: [],
    });
  });

  it("rejects scanner/login app reuse, insecure callback and Lab auth", () => {
    const result = validateFirstLivePilotConfiguration({
      ...validEnv,
      MICROSOFT_CLIENT_ID: "same-app",
      M365_GRAPH_CLIENT_ID: "same-app",
      M365_GRAPH_REDIRECT_URI:
        "http://localhost:3000/api/integrations/microsoft-365/callback",
      LAB_AUTH_ENABLED: "true",
    });

    expect(result.ok).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        "The Microsoft 365 scanner app must be separate from the CyberPilot sign-in app.",
        "M365_GRAPH_REDIRECT_URI must use https:// for the first LIVE pilot.",
        "M365_GRAPH_REDIRECT_URI must use the same public origin as BETTER_AUTH_URL.",
        "LAB_AUTH_ENABLED must not be true for the first LIVE pilot.",
      ]),
    );
  });

  it("rejects any remediation configuration, including future keys", () => {
    const result = validateFirstLivePilotConfiguration({
      ...validEnv,
      M365_REMEDIATION_CLIENT_ID: "writer-client",
      M365_REMEDIATION_FUTURE_FLAG: "enabled",
    });

    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain(
      "All M365_REMEDIATION_* values must be unset",
    );
    expect(result.errors[0]).toContain("M365_REMEDIATION_CLIENT_ID");
    expect(result.errors[0]).toContain("M365_REMEDIATION_FUTURE_FLAG");
  });

  it("rejects local HTTPS callbacks and hidden callback parameters", () => {
    const result = validateFirstLivePilotConfiguration({
      ...validEnv,
      BETTER_AUTH_URL: "https://localhost:3000",
      M365_GRAPH_REDIRECT_URI:
        "https://localhost:3000/api/integrations/microsoft-365/callback?next=elsewhere",
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toContain(
      "BETTER_AUTH_URL must use a public hostname for the first LIVE pilot.",
    );
    expect(result.errors).toContain(
      "M365_GRAPH_REDIRECT_URI must use a public hostname for the first LIVE pilot.",
    );
    expect(result.errors).toContain(
      "M365_GRAPH_REDIRECT_URI must not contain credentials, query parameters or fragments.",
    );
  });

  it("requires the public application origin without extra path or fragment", () => {
    const result = validateFirstLivePilotConfiguration({
      ...validEnv,
      BETTER_AUTH_URL: "https://pilot.cyberpilot.example/other#test",
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toContain(
      "BETTER_AUTH_URL must use the public application origin without a path.",
    );
    expect(result.errors).toContain(
      "BETTER_AUTH_URL must not contain credentials, query parameters or fragments.",
    );
  });

  it("requires the exact scanner callback path", () => {
    const result = validateFirstLivePilotConfiguration({
      ...validEnv,
      M365_GRAPH_REDIRECT_URI:
        "https://pilot.cyberpilot.example/api/integrations/microsoft-365/remediation/callback",
    });

    expect(result.ok).toBe(false);
    expect(result.errors).toContain(
      "M365_GRAPH_REDIRECT_URI must use the scanner callback path /api/integrations/microsoft-365/callback.",
    );
  });
});
