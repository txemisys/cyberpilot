export type ProductionConfigCheck = {
  ok: boolean;
  errors: string[];
};

const EXAMPLE_AUTH_SECRET = "replace-with-a-strong-random-secret";

function requireValue(
  env: NodeJS.ProcessEnv,
  key: string,
  errors: string[],
) {
  const value = env[key]?.trim();

  if (!value) {
    errors.push(`${key} is required.`);
  }

  return value;
}

function requireHttpsUrl(
  env: NodeJS.ProcessEnv,
  key: string,
  errors: string[],
) {
  const value = requireValue(env, key, errors);

  if (!value) {
    return;
  }

  try {
    const url = new URL(value);

    if (url.protocol !== "https:") {
      errors.push(`${key} must use https:// in production.`);
    }
  } catch {
    errors.push(`${key} must be a valid URL.`);
  }
}

export function validateProductionConfiguration(
  env: NodeJS.ProcessEnv,
): ProductionConfigCheck {
  const errors: string[] = [];

  requireValue(env, "DATABASE_URL", errors);

  const authSecret = requireValue(env, "AUTH_SECRET", errors);

  if (authSecret === EXAMPLE_AUTH_SECRET) {
    errors.push("AUTH_SECRET must not use the example value.");
  }

  if (authSecret && authSecret.length < 32) {
    errors.push("AUTH_SECRET must be at least 32 characters.");
  }

  requireHttpsUrl(env, "BETTER_AUTH_URL", errors);

  requireValue(env, "MICROSOFT_CLIENT_ID", errors);
  requireValue(env, "MICROSOFT_CLIENT_SECRET", errors);

  requireValue(env, "M365_GRAPH_CLIENT_ID", errors);
  requireValue(env, "M365_GRAPH_CLIENT_SECRET", errors);
  requireHttpsUrl(env, "M365_GRAPH_REDIRECT_URI", errors);

  if (env.LAB_AUTH_ENABLED === "true") {
    errors.push("LAB_AUTH_ENABLED must not be true in production.");
  }

  const remediationValues = [
    env.M365_REMEDIATION_CLIENT_ID?.trim(),
    env.M365_REMEDIATION_CLIENT_SECRET?.trim(),
    env.M365_REMEDIATION_REDIRECT_URI?.trim(),
  ];
  const remediationConfigured = remediationValues.filter(Boolean).length;

  if (remediationConfigured > 0 && remediationConfigured < 3) {
    errors.push(
      "M365 remediation configuration must be either fully configured or fully unset.",
    );
  }

  if (remediationConfigured === 3) {
    requireHttpsUrl(env, "M365_REMEDIATION_REDIRECT_URI", errors);
  }

  return {
    ok: errors.length === 0,
    errors,
  };
}

export function assertProductionConfiguration(env = process.env) {
  const result = validateProductionConfiguration(env);

  if (!result.ok) {
    throw new Error(
      `Invalid CyberPilot production configuration:\n- ${result.errors.join("\n- ")}`,
    );
  }
}
