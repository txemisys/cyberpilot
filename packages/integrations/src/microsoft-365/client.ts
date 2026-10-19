import {
  acquireMicrosoftGraphToken,
  inspectMicrosoftGraphApplicationRoles,
  MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES,
} from "./token";
import type {
  MicrosoftDirectoryUser,
  MicrosoftGraphCollection,
  MicrosoftOrganization,
  MicrosoftRoleAssignment,
  MicrosoftRoleDefinition,
  MicrosoftUserRegistrationDetails,
} from "./types";

const GRAPH_BASE_URL = new URL("https://graph.microsoft.com/v1.0/");
const MAX_GRAPH_ATTEMPTS = 3;
const MAX_GRAPH_RESPONSE_BYTES = 5 * 1024 * 1024;
const MAX_GRAPH_PAGES = 100;
const MAX_GRAPH_COLLECTION_ITEMS = 100_000;
const GRAPH_REQUEST_TIMEOUT_MS = 15_000;
const GRAPH_COLLECTION_TIMEOUT_MS = 2 * 60 * 1000;
const TRANSIENT_GRAPH_STATUSES = new Set([429, 500, 502, 503, 504]);

function sleep(milliseconds: number) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function getRetryDelayMs(response: Response, attempt: number) {
  const retryAfter = response.headers.get("retry-after");

  if (retryAfter) {
    const seconds = Number(retryAfter);

    if (Number.isFinite(seconds) && seconds >= 0) {
      return seconds * 1000;
    }

    const date = Date.parse(retryAfter);

    if (!Number.isNaN(date)) {
      return Math.max(0, date - Date.now());
    }
  }

  return 250 * 2 ** attempt;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function readRequiredString(
  input: Record<string, unknown>,
  key: string,
  resource: string,
) {
  const value = input[key];

  if (typeof value !== "string" || value.length === 0) {
    throw new MicrosoftGraphPayloadError(
      `Microsoft Graph returned invalid ${resource}: ${key} must be a non-empty string.`,
    );
  }

  return value;
}

function readOptionalString(
  input: Record<string, unknown>,
  key: string,
  resource: string,
) {
  const value = input[key];

  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value !== "string") {
    throw new MicrosoftGraphPayloadError(
      `Microsoft Graph returned invalid ${resource}: ${key} must be a string or null.`,
    );
  }

  return value;
}

function readOptionalBoolean(
  input: Record<string, unknown>,
  key: string,
  resource: string,
) {
  const value = input[key];

  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value !== "boolean") {
    throw new MicrosoftGraphPayloadError(
      `Microsoft Graph returned invalid ${resource}: ${key} must be a boolean or null.`,
    );
  }

  return value;
}

function validateOrganization(value: unknown): MicrosoftOrganization {
  if (!isRecord(value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned an invalid organization object.",
    );
  }

  const verifiedDomains = value.verifiedDomains;

  if (
    verifiedDomains !== undefined &&
    verifiedDomains !== null &&
    !Array.isArray(verifiedDomains)
  ) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned invalid organization: verifiedDomains must be an array.",
    );
  }

  return {
    id: readRequiredString(value, "id", "organization"),
    displayName: readOptionalString(value, "displayName", "organization"),
    verifiedDomains: Array.isArray(verifiedDomains)
      ? verifiedDomains.map((domain) => {
          if (!isRecord(domain)) {
            throw new MicrosoftGraphPayloadError(
              "Microsoft Graph returned an invalid verified domain.",
            );
          }

          return {
            name: readOptionalString(domain, "name", "verified domain"),
            isDefault: readOptionalBoolean(domain, "isDefault", "verified domain"),
            isInitial: readOptionalBoolean(domain, "isInitial", "verified domain"),
          };
        })
      : [],
  };
}

function validateUser(value: unknown): MicrosoftDirectoryUser {
  if (!isRecord(value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned an invalid user object.",
    );
  }

  return {
    id: readRequiredString(value, "id", "user"),
    displayName: readOptionalString(value, "displayName", "user"),
    userPrincipalName: readOptionalString(value, "userPrincipalName", "user"),
    accountEnabled: readOptionalBoolean(value, "accountEnabled", "user"),
    userType: readOptionalString(value, "userType", "user"),
    createdDateTime: readOptionalString(value, "createdDateTime", "user"),
  };
}

function validateRoleDefinition(value: unknown): MicrosoftRoleDefinition {
  if (!isRecord(value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned an invalid role definition object.",
    );
  }

  return {
    id: readRequiredString(value, "id", "role definition"),
    displayName: readRequiredString(value, "displayName", "role definition"),
    templateId: readOptionalString(value, "templateId", "role definition"),
    isBuiltIn: readOptionalBoolean(value, "isBuiltIn", "role definition"),
  };
}

function validateRoleAssignment(value: unknown): MicrosoftRoleAssignment {
  if (!isRecord(value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned an invalid role assignment object.",
    );
  }

  return {
    id: readRequiredString(value, "id", "role assignment"),
    principalId: readRequiredString(value, "principalId", "role assignment"),
    roleDefinitionId: readRequiredString(
      value,
      "roleDefinitionId",
      "role assignment",
    ),
    directoryScopeId: readOptionalString(
      value,
      "directoryScopeId",
      "role assignment",
    ),
  };
}

function validateRegistration(value: unknown): MicrosoftUserRegistrationDetails {
  if (!isRecord(value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned an invalid authentication registration object.",
    );
  }

  const methodsRegistered = value.methodsRegistered;

  if (
    methodsRegistered !== undefined &&
    methodsRegistered !== null &&
    (!Array.isArray(methodsRegistered) ||
      methodsRegistered.some((method) => typeof method !== "string"))
  ) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph returned invalid authentication registration: methodsRegistered must contain only strings.",
    );
  }

  return {
    id: readRequiredString(value, "id", "authentication registration"),
    isAdmin: readOptionalBoolean(value, "isAdmin", "authentication registration"),
    isMfaRegistered: readOptionalBoolean(
      value,
      "isMfaRegistered",
      "authentication registration",
    ),
    isMfaCapable: readOptionalBoolean(
      value,
      "isMfaCapable",
      "authentication registration",
    ),
    isPasswordlessCapable: readOptionalBoolean(
      value,
      "isPasswordlessCapable",
      "authentication registration",
    ),
    methodsRegistered: Array.isArray(methodsRegistered)
      ? methodsRegistered
      : null,
    lastUpdatedDateTime: readOptionalString(
      value,
      "lastUpdatedDateTime",
      "authentication registration",
    ),
    userPrincipalName: readOptionalString(
      value,
      "userPrincipalName",
      "authentication registration",
    ),
    userType: readOptionalString(value, "userType", "authentication registration"),
  };
}

function validateCollectionPage<T>(
  value: unknown,
  validateItem: (item: unknown) => T,
): MicrosoftGraphCollection<T> {
  if (!isRecord(value) || !Array.isArray(value.value)) {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph collection response must contain a value array.",
    );
  }

  const nextLink = value["@odata.nextLink"];

  if (nextLink !== undefined && typeof nextLink !== "string") {
    throw new MicrosoftGraphPayloadError(
      "Microsoft Graph @odata.nextLink must be a string.",
    );
  }

  return {
    value: value.value.map(validateItem),
    ...(typeof nextLink === "string" ? { "@odata.nextLink": nextLink } : {}),
  };
}

export class MicrosoftGraphError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "MicrosoftGraphError";
  }
}

export class MicrosoftGraphPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MicrosoftGraphPayloadError";
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
  applicationPermissions: {
    status: "EXACT" | "MISMATCH" | "ERROR";
    missing: string[];
    unexpected: string[];
  };
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

type MicrosoftGraphClientOptions = {
  collectionTimeoutMs?: number;
};

export class MicrosoftGraphClient {
  constructor(
    private readonly tenantId: string,
    private readonly options: MicrosoftGraphClientOptions = {},
  ) {}

  private async requestJson(
    pathOrUrl: string,
    deadlineAt?: number,
  ): Promise<unknown> {
    const url = resolveGraphUrl(pathOrUrl);

    for (let attempt = 0; attempt < MAX_GRAPH_ATTEMPTS; attempt += 1) {
      const remainingBeforeToken =
        deadlineAt === undefined ? undefined : deadlineAt - Date.now();

      if (
        remainingBeforeToken !== undefined &&
        remainingBeforeToken <= 0
      ) {
        throw new MicrosoftGraphError(
          "Microsoft Graph collection exceeded the maximum allowed duration.",
          504,
        );
      }

      const { access_token: accessToken } =
        await acquireMicrosoftGraphToken(this.tenantId, {
          ...(remainingBeforeToken === undefined
            ? {}
            : { timeoutMs: Math.min(10_000, remainingBeforeToken) }),
        });

      const remainingBeforeRequest =
        deadlineAt === undefined ? undefined : deadlineAt - Date.now();

      if (
        remainingBeforeRequest !== undefined &&
        remainingBeforeRequest <= 0
      ) {
        throw new MicrosoftGraphError(
          "Microsoft Graph collection exceeded the maximum allowed duration.",
          504,
        );
      }

      let response: Response;

      try {
        response = await fetch(url, {
          headers: {
            authorization: `Bearer ${accessToken}`,
            accept: "application/json",
          },
          cache: "no-store",
          signal: AbortSignal.timeout(
            remainingBeforeRequest === undefined
              ? GRAPH_REQUEST_TIMEOUT_MS
              : Math.min(GRAPH_REQUEST_TIMEOUT_MS, remainingBeforeRequest),
          ),
        });
      } catch (error) {
        if (error instanceof DOMException && error.name === "TimeoutError") {
          throw new MicrosoftGraphError(
            deadlineAt !== undefined && Date.now() >= deadlineAt
              ? "Microsoft Graph collection exceeded the maximum allowed duration."
              : "Microsoft Graph request timed out.",
            504,
          );
        }

        throw error;
      }

      if (!response.ok) {
        const shouldRetry =
          TRANSIENT_GRAPH_STATUSES.has(response.status) &&
          attempt < MAX_GRAPH_ATTEMPTS - 1;

        if (!shouldRetry) {
          throw new MicrosoftGraphError(
            `Microsoft Graph request failed with status ${response.status}.`,
            response.status,
          );
        }

        const retryDelayMs = getRetryDelayMs(response, attempt);

        if (
          deadlineAt !== undefined &&
          Date.now() + retryDelayMs >= deadlineAt
        ) {
          throw new MicrosoftGraphError(
            "Microsoft Graph collection exceeded the maximum allowed duration.",
            504,
          );
        }

        await sleep(retryDelayMs);
        continue;
      }

      const declaredLength = Number(response.headers.get("content-length"));

      if (
        Number.isFinite(declaredLength) &&
        declaredLength > MAX_GRAPH_RESPONSE_BYTES
      ) {
        throw new MicrosoftGraphPayloadError(
          "Microsoft Graph response exceeded the maximum allowed size.",
        );
      }

      const body = await response.text();

      if (Buffer.byteLength(body, "utf8") > MAX_GRAPH_RESPONSE_BYTES) {
        throw new MicrosoftGraphPayloadError(
          "Microsoft Graph response exceeded the maximum allowed size.",
        );
      }

      try {
        return JSON.parse(body) as unknown;
      } catch {
        throw new MicrosoftGraphPayloadError(
          "Microsoft Graph returned invalid JSON.",
        );
      }
    }

    throw new MicrosoftGraphError(
      "Microsoft Graph request exhausted retry attempts.",
      503,
    );
  }

  private async requestCollection<T>(
    pathOrUrl: string,
    validateItem: (item: unknown) => T,
    deadlineAt?: number,
  ) {
    return validateCollectionPage(
      await this.requestJson(pathOrUrl, deadlineAt),
      validateItem,
    );
  }

  private async listAll<T>(
    path: string,
    validateItem: (item: unknown) => T,
  ): Promise<T[]> {
    const items: T[] = [];
    let nextUrl: string | undefined = path;
    let pages = 0;
    const deadlineAt =
      Date.now() +
      (this.options.collectionTimeoutMs ?? GRAPH_COLLECTION_TIMEOUT_MS);

    while (nextUrl) {
      pages += 1;

      if (pages > MAX_GRAPH_PAGES) {
        throw new MicrosoftGraphPayloadError(
          "Microsoft Graph collection exceeded the maximum page count.",
        );
      }

      const page: MicrosoftGraphCollection<T> =
        await this.requestCollection(nextUrl, validateItem, deadlineAt);

      if (items.length + page.value.length > MAX_GRAPH_COLLECTION_ITEMS) {
        throw new MicrosoftGraphPayloadError(
          "Microsoft Graph collection exceeded the maximum item count.",
        );
      }

      items.push(...page.value);
      nextUrl = page["@odata.nextLink"];
    }

    return items;
  }

  async getOrganization(): Promise<MicrosoftOrganization> {
    const result = await this.requestCollection(
      "/organization?$select=id,displayName,verifiedDomains",
      validateOrganization,
    );

    const organization = result.value[0];

    if (!organization) {
      throw new MicrosoftGraphPayloadError(
        "Microsoft Graph returned no organization.",
      );
    }

    return organization;
  }

  async listUsers(): Promise<MicrosoftDirectoryUser[]> {
    return this.listAll(
      "/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999",
      validateUser,
    );
  }

  async listRoleDefinitions(): Promise<MicrosoftRoleDefinition[]> {
    return this.listAll(
      "/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn&$top=999",
      validateRoleDefinition,
    );
  }

  async listRoleAssignments(): Promise<MicrosoftRoleAssignment[]> {
    return this.listAll(
      "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId&$top=999",
      validateRoleAssignment,
    );
  }

  async listUserRegistrationDetails(): Promise<
    MicrosoftUserRegistrationDetails[]
  > {
    return this.listAll(
      "/reports/authenticationMethods/userRegistrationDetails",
      validateRegistration,
    );
  }

  async probeReadOnlyAccess(): Promise<MicrosoftGraphReadOnlyProbe> {
    let applicationPermissions: MicrosoftGraphReadOnlyProbe["applicationPermissions"] = {
      status: "ERROR",
      missing: [...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES],
      unexpected: [],
    };

    try {
      const { access_token: accessToken } =
        await acquireMicrosoftGraphToken(this.tenantId);
      const roles = inspectMicrosoftGraphApplicationRoles(accessToken);

      applicationPermissions = {
        status: roles.exact ? "EXACT" : "MISMATCH",
        missing: roles.missing,
        unexpected: roles.unexpected,
      };
    } catch {
      applicationPermissions = {
        status: "ERROR",
        missing: [...MICROSOFT_GRAPH_READONLY_APPLICATION_ROLES],
        unexpected: [],
      };
    }

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
          this.requestCollection(
            "/users?$select=id&$top=1",
            validateUser,
          ),
      ],
      [
        "roleDefinitions",
        () =>
          this.requestCollection(
            "/roleManagement/directory/roleDefinitions?$select=id,displayName&$top=1",
            validateRoleDefinition,
          ),
      ],
      [
        "roleAssignments",
        () =>
          this.requestCollection(
            "/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId&$top=1",
            validateRoleAssignment,
          ),
      ],
      [
        "authenticationRegistration",
        () =>
          this.requestCollection(
            "/reports/authenticationMethods/userRegistrationDetails?$filter=userPrincipalName eq '__cyberpilot_readonly_probe__'",
            validateRegistration,
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
      applicationPermissions,
      checks,
    };
  }
}
