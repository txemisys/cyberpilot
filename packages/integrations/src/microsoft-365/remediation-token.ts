import { assertMicrosoftTenantId } from "./token";

type TokenResponse = {
  access_token: string;
  expires_in: number;
  token_type: string;
};

export function isMicrosoftRemediationExecutorConfigured() {
  return Boolean(
    process.env.M365_REMEDIATION_CLIENT_ID &&
      process.env.M365_REMEDIATION_CLIENT_SECRET,
  );
}

export async function acquireMicrosoftRemediationToken(tenantId: string) {
  assertMicrosoftTenantId(tenantId);

  const clientId = process.env.M365_REMEDIATION_CLIENT_ID;
  const clientSecret = process.env.M365_REMEDIATION_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error("Microsoft 365 remediation executor is not configured.");
  }

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "client_credentials",
    scope: "https://graph.microsoft.com/.default",
  });

  const response = await fetch(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
      cache: "no-store",
    },
  );

  if (!response.ok) {
    throw new Error(
      `Microsoft remediation token request failed with status ${response.status}.`,
    );
  }

  const token = (await response.json()) as TokenResponse;

  if (!token.access_token) {
    throw new Error(
      "Microsoft remediation token response did not contain an access token.",
    );
  }

  return token;
}
