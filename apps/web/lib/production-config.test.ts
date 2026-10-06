import { describe, expect, it } from "vitest";

import { validateProductionConfiguration } from "./production-config";

const validEnv: NodeJS.ProcessEnv = {
  DATABASE_URL: "postgresql://cyberpilot:secret@db.internal:5432/cyberpilot",
  AUTH_SECRET: "0123456789abcdef0123456789abcdef",
  BETTER_AUTH_URL: "https://staging.cyberpilot.example",
  LAB_AUTH_ENABLED: "false",
  MICROSOFT_CLIENT_ID: "login-client",
  MICROSOFT_CLIENT_SECRET: "login-secret",
  M365_GRAPH_CLIENT_ID: "scanner-client",
  M365_GRAPH_CLIENT_SECRET: "scanner-secret",
  M365_GRAPH_REDIRECT_URI:
    "https://staging.cyberpilot.example/api/integrations/microsoft-365/callback",
};

describe("production configuration", () => {
  it("accepts a complete read-only production configuration", () => {
    expect(validateProductionConfiguration(validEnv)).toEqual({
      ok: true,
      errors: [],
    });
  });

  it("rejects Local Lab auth and insecure public URLs", () => {
    const result = validateProductionConfiguration({
      ...validEnv,
      LAB_AUTH_ENABLED: "true",
      BETTER_AUTH_URL: "http://localhost:3000",
      M365_GRAPH_REDIRECT_URI:
        "http://localhost:3000/api/integrations/microsoft-365/callback",
    });

    expect(result.ok).toBe(false);
    expect(result.errors).toEqual(
      expect.arrayContaining([
        "LAB_AUTH_ENABLED must not be true in production.",
        "BETTER_AUTH_URL must use https:// in production.",
        "M365_GRAPH_REDIRECT_URI must use https:// in production.",
      ]),
    );
  });

  it("rejects partial remediation configuration", () => {
    const result = validateProductionConfiguration({
      ...validEnv,
      M365_REMEDIATION_CLIENT_ID: "executor-client",
    });

    expect(result.ok).toBe(false);
    expect(result.errors).toContain(
      "M365 remediation configuration must be either fully configured or fully unset.",
    );
  });
});
