import { db } from "@cyberpilot/database";
import { buildIntegratedRiskDigest,
  verifyIntegratedRiskDigest, type IntegratedRiskInput,
  type IntegratedRiskDigest,
} from "./integrated-risk-engine";

export type IntegratedReviewer = {
  organizationId:string;userId:string;
  role:"OWNER"|"ADMIN"|"MEMBER"|"AUDITOR";
};
export class IntegratedAccessError extends Error {
  constructor(public readonly code:string){super(code);}
}
const caps={
  evidence:500,findings:500,assessments:150,declaredActions:500,
} as const;
function strictId(x:string){
  return typeof x==="string"&&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
}
const iso=(date:Date|null)=>date?.toISOString()??null;
export async function collectIntegratedRiskDigest(
  actor:IntegratedReviewer,asOf=new Date().toISOString()
):Promise<IntegratedRiskDigest>{
  if(!strictId(actor.organizationId)||!strictId(actor.userId))
    throw new IntegratedAccessError("ACTOR_SCOPE_INVALID");
  if(!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    throw new IntegratedAccessError("REVIEWER_PERMISSION_REQUIRED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)
    throw new IntegratedAccessError("CURRENT_MEMBERSHIP_REQUIRED");
  const organizationId=actor.organizationId;
  const [evidence,findings,assessments,declaredActions]=await Promise.all([
    db.securityEvidence.findMany({
      where:{organizationId},
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
      take:caps.evidence+1,
      select:{id:true,organizationId:true,source:true,domain:true,
        controlId:true,state:true,scope:true,observedAt:true,
        createdAt:true,details:true},
    }),
    db.securityFinding.findMany({
      where:{organizationId},
      orderBy:[{lastSeenAt:"desc"},{id:"asc"}],
      take:caps.findings+1,
      select:{id:true,organizationId:true,ruleId:true,key:true,
        severity:true,status:true,title:true,description:true,
        lastSeenAt:true,evidence:true},
    }),
    db.multiSourceV2Assessment.findMany({
      where:{organizationId},
      orderBy:[{evaluatedAt:"desc"},{id:"asc"}],
      take:caps.assessments+1,
      select:{id:true,organizationId:true,snapshotId:true,
        modelId:true,modelRevision:true,status:true,score:true,
        coveragePercent:true,sourceClass:true,evaluatedAt:true,
        reportDigest:true,manifestDigest:true,verifiedControls:true,
        totalControls:true},
    }),
    db.baselineFollowUp.findMany({
      where:{organizationId},
      orderBy:[{updatedAt:"desc"},{id:"asc"}],
      take:caps.declaredActions+1,
      select:{id:true,organizationId:true,questionId:true,
        sourceDraftRevision:true,status:true,revision:true,
        dueAt:true,ownerUserId:true,updatedAt:true},
    }),
  ]);
  const input:IntegratedRiskInput={
    organizationId,evaluatedAt:asOf,
    sourceLimits:caps,
    countOfRecords:{
      evidence:evidence.length,
      findings:findings.length,
      assessments:assessments.length,
      declaredActions:declaredActions.length,
    },
    evidence:evidence.slice(0,caps.evidence).map(x=>({
      ...x,observedAt:iso(x.observedAt),
      createdAt:x.createdAt.toISOString(),
    })),
    findings:findings.slice(0,caps.findings).map(x=>({
      ...x,lastSeenAt:x.lastSeenAt.toISOString(),
    })),
    assessments:assessments.slice(0,caps.assessments).map(x=>({
      ...x,evaluatedAt:x.evaluatedAt.toISOString(),
    })),
    declaredActions:declaredActions.slice(0,caps.declaredActions).map(x=>({
      ...x,dueAt:iso(x.dueAt),updatedAt:x.updatedAt.toISOString(),
    })),
  };
  const report=buildIntegratedRiskDigest(input);
  if(!verifyIntegratedRiskDigest(report,organizationId).valid)
    throw Error("INTEGRATED_DIGEST_INTEGRITY_INVALID");
  return report;
}
