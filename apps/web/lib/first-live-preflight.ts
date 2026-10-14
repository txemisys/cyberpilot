export type FirstLivePilotConfigCheck = {
  ok: boolean;
  errors: string[];
};

const SCANNER_CALLBACK_PATH = "/api/integrations/microsoft-365/callback";

function value(env: NodeJS.ProcessEnv, key: string) {
  return env[key]?.trim() ?? "";
}

function parseHttpsUrl(
  env: NodeJS.ProcessEnv,
  key: string,
  errors: string[],
) {
  const raw = value(env, key);

  if (!raw) {
    errors.push(`${key} is required for the first LIVE pilot.`);
    return null;
  }

  try {
    const url = new URL(raw);

    if (url.protocol !== "https:") {
      errors.push(`${key} must use https:// for the first LIVE pilot.`);
    }

    return url;
  } catch {
    errors.push(`${key} must be a valid URL.`);
    return null;
  }
}

export function validateFirstLivePilotConfiguration(
  env: NodeJS.ProcessEnv,
): FirstLivePilotConfigCheck {
  const errors: string[] = [];

  const scannerClientId = value(env, "M365_GRAPH_CLIENT_ID");
  const scannerSecret = value(env, "M365_GRAPH_CLIENT_SECRET");
  const loginClientId = value(env, "MICROSOFT_CLIENT_ID");

  if (!scannerClientId) {
    errors.push("M365_GRAPH_CLIENT_ID is required for the first LIVE pilot.");
  }

  if (!scannerSecret) {
    errors.push("M365_GRAPH_CLIENT_SECRET is required for the first LIVE pilot.");
  }

  if (!loginClientId) {
    errors.push("MICROSOFT_CLIENT_ID is required for the first LIVE pilot.");
  }

  if (scannerClientId && loginClientId && scannerClientId === loginClientId) {
    errors.push(
      "The Microsoft 365 scanner app must be separate from the CyberPilot sign-in app.",
    );
  }

  const authUrl = parseHttpsUrl(env, "BETTER_AUTH_URL", errors);
  const scannerRedirect = parseHttpsUrl(
    env,
    "M365_GRAPH_REDIRECT_URI",
    errors,
  );

  if (scannerRedirect && scannerRedirect.pathname !== SCANNER_CALLBACK_PATH) {
    errors.push(
      `M365_GRAPH_REDIRECT_URI must use the scanner callback path ${SCANNER_CALLBACK_PATH}.`,
    );
  }

  if (
    authUrl &&
    scannerRedirect &&
    authUrl.origin !== scannerRedirect.origin
  ) {
    errors.push(
      "M365_GRAPH_REDIRECT_URI must use the same public origin as BETTER_AUTH_URL.",
    );
  }

  if (env.LAB_AUTH_ENABLED === "true") {
    errors.push("LAB_AUTH_ENABLED must not be true for the first LIVE pilot.");
  }

  const remediationKeys = Object.keys(env)
    .filter(
      (key) =>
        key.startsWith("M365_REMEDIATION_") && Boolean(value(env, key)),
    )
    .sort();

  if (remediationKeys.length > 0) {
    errors.push(
      `All M365_REMEDIATION_* values must be unset for the first LIVE pilot. Configured: ${remediationKeys.join(", ")}.`,
    );
  }

  return {
    ok: errors.length === 0,
    errors,
  };
}

export function assertFirstLivePilotConfiguration(env = process.env) {
  const result = validateFirstLivePilotConfiguration(env);

  if (!result.ok) {
    throw new Error(
      `Invalid first LIVE pilot configuration:\n- ${result.errors.join("\n- ")}`,
    );
  }
}
