export type MicrosoftVerifiedDomain = {
  name?: string | null;
  isDefault?: boolean | null;
  isInitial?: boolean | null;
};

export type MicrosoftOrganization = {
  id: string;
  displayName?: string | null;
  verifiedDomains?: MicrosoftVerifiedDomain[];
};

export type MicrosoftDirectoryUser = {
  id: string;
  displayName?: string | null;
  userPrincipalName?: string | null;
  accountEnabled?: boolean | null;
  userType?: string | null;
  createdDateTime?: string | null;
};

export type MicrosoftRoleDefinition = {
  id: string;
  displayName: string;
  templateId?: string | null;
  isBuiltIn?: boolean | null;
};

export type MicrosoftRoleAssignment = {
  id: string;
  principalId: string;
  roleDefinitionId: string;
  directoryScopeId?: string | null;
};

export type MicrosoftGraphCollection<T> = {
  value: T[];
  "@odata.nextLink"?: string;
};
