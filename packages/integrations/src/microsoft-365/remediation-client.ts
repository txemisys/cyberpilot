import {
  acquireMicrosoftRemediationToken,
  isMicrosoftRemediationExecutorConfigured,
} from "./remediation-token";

const GRAPH_BASE_URL = new URL("https://graph.microsoft.com/v1.0/");

export class MicrosoftRemediationError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "MicrosoftRemediationError";
  }
}

function roleAssignmentUrl(roleAssignmentId: string) {
  if (!roleAssignmentId || /[/?#]/.test(roleAssignmentId)) {
    throw new Error("Invalid Microsoft role assignment ID.");
  }

  return new URL(
    `roleManagement/directory/roleAssignments/${encodeURIComponent(
      roleAssignmentId,
    )}`,
    GRAPH_BASE_URL,
  );
}

export class MicrosoftRemediationClient {
  constructor(private readonly tenantId: string) {}

  isConfigured() {
    return isMicrosoftRemediationExecutorConfigured();
  }

  private async request(
    url: URL,
    init?: RequestInit,
  ): Promise<Response> {
    const { access_token: accessToken } =
      await acquireMicrosoftRemediationToken(this.tenantId);

    if (url.origin !== GRAPH_BASE_URL.origin) {
      throw new Error("Refusing to request an unexpected Microsoft Graph URL.");
    }

    return fetch(url, {
      ...init,
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
        ...init?.headers,
      },
      cache: "no-store",
    });
  }

  async probeDirectoryRoleManagement() {
    const url = new URL(
      "roleManagement/directory/roleAssignments?$top=1&$select=id",
      GRAPH_BASE_URL,
    );
    const response = await this.request(url);

    if (!response.ok) {
      throw new MicrosoftRemediationError(
        `Microsoft remediation permission probe failed with status ${response.status}.`,
        response.status,
      );
    }

    return true;
  }

  async getDirectoryRoleAssignment(roleAssignmentId: string) {
    const response = await this.request(roleAssignmentUrl(roleAssignmentId));

    if (response.status === 404) {
      return null;
    }

    if (!response.ok) {
      throw new MicrosoftRemediationError(
        `Microsoft remediation verification failed with status ${response.status}.`,
        response.status,
      );
    }

    return (await response.json()) as {
      id: string;
      principalId: string;
      roleDefinitionId: string;
      directoryScopeId?: string | null;
    };
  }

  async deleteDirectoryRoleAssignment(roleAssignmentId: string) {
    const response = await this.request(roleAssignmentUrl(roleAssignmentId), {
      method: "DELETE",
    });

    if (response.status === 404) {
      return { alreadyAbsent: true };
    }

    if (response.status !== 204) {
      throw new MicrosoftRemediationError(
        `Microsoft remediation action failed with status ${response.status}.`,
        response.status,
      );
    }

    return { alreadyAbsent: false };
  }
}
