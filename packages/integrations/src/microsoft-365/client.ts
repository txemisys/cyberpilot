import { acquireMicrosoftGraphToken } from "./token";
import type {
  MicrosoftDirectoryUser,
  MicrosoftGraphCollection,
  MicrosoftOrganization,
  MicrosoftRoleAssignment,
  MicrosoftRoleDefinition,
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
}
