const TENANT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES = [
  "AuditLog.Read.All",
  "Organization.Read.All",
  "RoleManagement.Read.Directory",
  "User.Read.All",
] as const;

const MICROSOFT_TOKEN_REQUEST_TIMEOUT_MS = 10_000;

type TokenResponse = {
  access_token: string;
  expires_in: number;
  token_type: string;
};

type AccessTokenPayload = {
  roles?: unknown;
};

type MicrosoftGraphTokenRequestOptions = {
  fetcher?: typeof fetch;
  timeoutMs?: number;
};

export class MicrosoftGraphTokenError extends Error {
  constructor(
    message: string,
    readonly kind:
      | "AUTHORIZATION"
      | "UNAVAILABLE"
      | "CONFIGURATION"
      | "INVALID_RESPONSE",
    readonly status?: number,
  ) {
    super(message);
    this.name = "MicrosoftGraphTokenError";
  }
}

export function assertMicrosoftTenantId(tenantId: string) {
  if (!TENANT_ID_PATTERN.test(tenantId)) {
    throw new Error("Invalid Microsoft tenant ID.");
  }
}

export function inspectMicrosoftGraphApplicationRoles(accessToken: string) {
  const parts = accessToken.split(".");

  if (parts.length < 2) {
    throw new Error("Microsoft Graph access token is not a JWT.");
  }

  const payloadPart = parts[1];

  if (!payloadPart) {
    throw new Error("Microsoft Graph access token is not a JWT.");
  }

  let payload: AccessTokenPayload;

  try {
    payload = JSON.parse(
      Buffer.from(payloadPart, "base64url").toString("utf8"),
    ) as AccessTokenPayload;
  } catch {
    throw new Error("Microsoft Graph access token payload is invalid.");
  }

  const roles = Array.isArray(payload.roles)
    ? payload.roles.filter((role): role is string => typeof role === "string")
    : [];

  const granted = [...new Set(roles)].sort();
  const required = [...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES].sort();
  const grantedSet = new Set(granted);
  const requiredSet = new Set<string>(required);
  const missing = required.filter((role) => !grantedSet.has(role));
  const unexpected = granted.filter((role) => !requiredSet.has(role));

  return {
    granted,
    missing,
    unexpected,
    exact: missing.length === 0 && unexpected.length === 0,
  };
}

export async function acquireMicrosoftGraphToken(
  tenantId: string,
  options: MicrosoftGraphTokenRequestOptions = {},
) {
  assertMicrosoftTenantId(tenantId);

  const clientId = process.env.M365_GRAPH_CLIENT_ID;
  const clientSecret = process.env.M365_GRAPH_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new MicrosoftGraphTokenError(
      "Microsoft 365 Graph credentials are not configured.",
      "CONFIGURATION",
    );
  }

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "client_credentials",
    scope: "https://graph.microsoft.com/.default",
  });

  const fetcher = options.fetcher ?? fetch;
  const timeoutMs = options.timeoutMs ?? MICROSOFT_TOKEN_REQUEST_TIMEOUT_MS;
  let response: Response;

  try {
    response = await fetcher(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
        cache: "no-store",
        signal: AbortSignal.timeout(timeoutMs),
      },
    );
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new MicrosoftGraphTokenError(
        "Microsoft token request timed out.",
        "UNAVAILABLE",
      );
    }

    throw error;
  }

  if (!response.ok) {
    const kind =
      response.status === 400 ||
      response.status === 401 ||
      response.status === 403
        ? "AUTHORIZATION"
        : response.status === 429 || response.status >= 500
          ? "UNAVAILABLE"
          : "INVALID_RESPONSE";

    throw new MicrosoftGraphTokenError(
      `Microsoft token request failed with status ${response.status}.`,
      kind,
      response.status,
    );
  }

  let token: TokenResponse;

  try {
    token = (await response.json()) as TokenResponse;
  } catch {
    throw new MicrosoftGraphTokenError(
      "Microsoft token response was not valid JSON.",
      "INVALID_RESPONSE",
    );
  }

  if (!token.access_token) {
    throw new MicrosoftGraphTokenError(
      "Microsoft token response did not contain an access token.",
      "INVALID_RESPONSE",
    );
  }

  return token;
}

export function getMicrosoftGraphScannerConfiguration() {
  const missing: string[] = [];

  if (!process.env.M365_GRAPH_CLIENT_ID) {
    missing.push("M365_GRAPH_CLIENT_ID");
  }

  if (!process.env.M365_GRAPH_CLIENT_SECRET) {
    missing.push("M365_GRAPH_CLIENT_SECRET");
  }

  return {
    configured: missing.length === 0,
    missing,
  };
}
