import { db } from "@cyberpilot/database";

export type LabRoleAssignmentEvidence = {
  roleAssignmentId: string;
  userId: string;
  roleDefinitionId: string;
};

export async function executeLabRoleAssignmentRemoval(
  integrationId: string,
  evidence: LabRoleAssignmentEvidence,
) {
  const currentAssignment = await db.directoryRoleAssignment.findUnique({
    where: {
      integrationId_externalId: {
        integrationId,
        externalId: evidence.roleAssignmentId,
      },
    },
    select: {
      principalExternalId: true,
      roleDefinitionExternalId: true,
    },
  });

  if (currentAssignment) {
    if (
      currentAssignment.principalExternalId !== evidence.userId ||
      currentAssignment.roleDefinitionExternalId !== evidence.roleDefinitionId
    ) {
      throw new Error("REMEDIATION_EVIDENCE_MISMATCH");
    }

    await db.directoryRoleAssignment.delete({
      where: {
        integrationId_externalId: {
          integrationId,
          externalId: evidence.roleAssignmentId,
        },
      },
    });
  }

  const verification = await db.directoryRoleAssignment.findUnique({
    where: {
      integrationId_externalId: {
        integrationId,
        externalId: evidence.roleAssignmentId,
      },
    },
    select: {
      id: true,
    },
  });

  if (verification) {
    throw new Error("REMEDIATION_VERIFICATION_FAILED");
  }

  return {
    roleAssignmentId: evidence.roleAssignmentId,
    principalId: evidence.userId,
    roleDefinitionId: evidence.roleDefinitionId,
    verifiedAbsent: true as const,
  };
}
