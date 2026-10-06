import { acquireMicrosoftGraphToken } from "./token";
import type {
  MicrosoftDirectoryUser,
  MicrosoftGraphCollection,
  MicrosoftOrganization,
  MicrosoftRoleAssignment,
  MicrosoftRoleDefinition,
  MicrosoftUserRegistrationDetails,
} from "./types";

const GRAPH_BASE_URL = new URL("https://graph.microsoft.com/v1.0/");

export class MicrosoftGraphError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "MicrosoftGraphError";
  }
}

function resolveGraphUrl(pathOrUrl: string) {
  const url = pathOrUrl.startsWith("https://")
    ? new URL(pathOrUrl)
    : new URL(pathOrUrl.replace(/^\//, ""), GRAPH_BASE_URL);

  if (
    url.origin !== GRAPH_BASE_URL.origin ||
    !url.pathname.startsWith(GRAPH_BASE_URL.pathname)
  ) {
    throw new Error("Refusing to request an unexpected Microsoft Graph URL.");
  }

  return url;
}

export type MicrosoftGraphReadOnlyProbeCheck = {
  status: "AVAILABLE" | "PERMISSION_REQUIRED" | "ERROR";
  httpStatus?: number;
};

export type MicrosoftGraphReadOnlyProbe = {
  tenantId: string;
  checks: {
    organization: MicrosoftGraphReadOnlyProbeCheck;
    users: MicrosoftGraphReadOnlyProbeCheck;
    roleDefinitions: MicrosoftGraphReadOnlyProbeCheck;
    roleAssignments: MicrosoftGraphReadOnlyProbeCheck;
    authenticationRegistration: MicrosoftGraphReadOnlyProbeCheck;
  };
};

function classifyProbeError(error: unknown): MicrosoftGraphReadOnlyProbeCheck {
  if (error instanceof MicrosoftGraphError) {
    return {
      status: error.status === 403 ? "PERMISSION_REQUIRED" : "ERROR",
      httpStatus: error.status,
    };
  }

  return { status: "ERROR" };
}

export class MicrosoftGraphClient {
  constructor(private readonly tenantId: string) {}

  private async request<T>(pathOrUrl: string): Promise<T> {
    const { access_token: accessToken } =
      await acquireMicrosoftGraphToken(this.tenantId);

    const url = resolveGraphUrl(pathOrUrl);

    const response = await fetch(url, {
      headers: {
        authorization: `Bearer ${accessToken}`,
        accept: "application/json",
      },
      cache: "no-store",
    });

    if (!response.ok) {
      throw new MicrosoftGraphError(
        `Microsoft Graph request failed with status ${response.status}.`,
        response.status,
      );
    }

    return (await response.json()) as T;
  }

  private async listAll<T>(path: string): Promise<T[]> {
    const items: T[] = [];
    let nextUrl: string | undefined = path;

    while (nextUrl) {
      const page: MicrosoftGraphCollection<T> =
        await this.request<MicrosoftGraphCollection<T>>(nextUrl);

      items.push(...page.value);
      nextUrl = page["@odata.nextLink"];
    }

    return items;
  }

  async getOrganization(): Promise<MicrosoftOrganization> {
    const result = await this.request<
      MicrosoftGraphCollection<MicrosoftOrganization>
    >("/organization?$select=id,displayName,verifiedDomains");

    const organization = result.value[0];

    if (!organization) {
      throw new Error("Microsoft Graph returned no organization.");
    }

    return organization;
  }

  async listUsers(): Promise<MicrosoftDirectoryUser[]> {
    return this.listAll<MicrosoftDirectoryUser>(
      "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999",
    );
  }

  async listRoleDefinitions(): Promise<MicrosoftRoleDefinition[]> {
    return this.listAll<MicrosoftRoleDefinition>(
      "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn&$top=999",
    );
  }

  async listRoleAssignments(): Promise<MicrosoftRoleAssignment[]> {
    return this.listAll<MicrosoftRoleAssignment>(
      "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId&$top=999",
    );
  }

  async listUserRegistrationDetails(): Promise<
    MicrosoftUserRegistrationDetails[]
  > {
    return this.listAll<MicrosoftUserRegistrationDetails>(
      "/reports/authenticationMethods/userRegistrationDetails",
    );
  }

  async probeReadOnlyAccess(): Promise<MicrosoftGraphReadOnlyProbe> {
    const checks: MicrosoftGraphReadOnlyProbe["checks"] = {
      organization: { status: "ERROR" },
      users: { status: "ERROR" },
      roleDefinitions: { status: "ERROR" },
      roleAssignments: { status: "ERROR" },
      authenticationRegistration: { status: "ERROR" },
    };

    try {
      const organization = await this.getOrganization();

      if (organization.id.toLowerCase() !== this.tenantId.toLowerCase()) {
        throw new Error("Microsoft tenant verification failed during probe.");
      }

      checks.organization = { status: "AVAILABLE" };
    } catch (error) {
      checks.organization = classifyProbeError(error);
    }

    const probes: Array<
      [keyof MicrosoftGraphReadOnlyProbe["checks"], () => Promise<unknown>]
    > = [
      [
        "users",
        () =>
          this.request<MicrosoftGraphCollection<MicrosoftDirectoryUser>>(
            "/users?$select=id&$top=1",
          ),
      ],
      [
        "roleDefinitions",
        () =>
          this.request<MicrosoftGraphCollection<MicrosoftRoleDefinition>>(
            "/roleManagement/directory/roleDefinitions?$select=id&$top=1",
          ),
      ],
      [
        "roleAssignments",
        () =>
          this.request<MicrosoftGraphCollection<MicrosoftRoleAssignment>>(
            "/roleManagement/directory/roleAssignments?$select=id&$top=1",
          ),
      ],
      [
        "authenticationRegistration",
        () =>
          this.request<MicrosoftGraphCollection<MicrosoftUserRegistrationDetails>>(
            "/reports/authenticationMethods/userRegistrationDetails?$filter=userPrincipalName eq '__cyberpilot_readonly_probe__'",
          ),
      ],
    ];

    for (const [name, probe] of probes) {
      try {
        await probe();
        checks[name] = { status: "AVAILABLE" };
      } catch (error) {
        checks[name] = classifyProbeError(error);
      }
    }

    return {
      tenantId: this.tenantId,
      checks,
    };
  }
}
