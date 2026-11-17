import {db} from "@cyberpilot/database";
import type{IntegratedReviewer}from "./integrated-risk-service";
import {buildTrendReport,verifyTrendReport}from "./offline-longitudinal-trends";
export async function collectOfflineLongitudinalTrends(
 actor:IntegratedReviewer,asOf=new Date().toISOString()){
 if(!["OWNER","ADMIN","AUDITOR"].includes(actor.role))
  throw Error("REVIEW_ROLE_REQUIRED");
 const membership=await db.membership.findFirst({
  where:{organizationId:actor.organizationId,userId:actor.userId},
  select:{role:true},
 });
 if(!membership||membership.role!==actor.role)
  throw Error("CURRENT_TENANT_MEMBERSHIP_REQUIRED");
 const organizationId=actor.organizationId;
 const [snapshots,actions,events]=await Promise.all([
  db.multiSourceV2Assessment.findMany({
   where:{organizationId},take:201,
   orderBy:[{evaluatedAt:"desc"},{id:"desc"}],
   select:{
    id:true,organizationId:true,snapshotId:true,
    modelId:true,modelRevision:true,evaluatedAt:true,
    score:true,status:true,coveragePercent:true,
    verifiedControls:true,totalControls:true,
    riskPoints:true,sourceClass:true,
    manifestDigest:true,reportDigest:true,
   },
  }),
  db.integratedRiskAction.findMany({
   where:{organizationId},take:501,
   orderBy:[{updatedAt:"desc"},{id:"desc"}],
   select:{id:true,organizationId:true,riskKey:true,status:true,
    priority:true,revision:true,ownerUserId:true,updatedAt:true,dueAt:true},
  }),
  db.integratedRiskActionEvent.findMany({
   where:{organizationId},take:2001,
   orderBy:[{occurredAt:"desc"},{id:"desc"}],
   select:{organizationId:true,actionId:true,revision:true,
    kind:true,previousStatus:true,nextStatus:true,
    actorUserId:true,occurredAt:true},
  }),
 ]);
 const report=buildTrendReport({
  organizationId,evaluatedAt:asOf,
  assessments:snapshots.slice(0,200).map(x=>({
   ...x,evaluatedAt:x.evaluatedAt.toISOString(),
  })),
  actions:actions.slice(0,500).map(x=>({
   actionId:x.id,organizationId:x.organizationId,
   riskKey:x.riskKey,status:x.status,priority:x.priority,
   revision:x.revision,ownerUserId:x.ownerUserId,
   updatedAt:x.updatedAt.toISOString(),
   dueAt:x.dueAt?.toISOString()??null,
  })),
  events:events.slice(0,2000).map(x=>({
   ...x,occurredAt:x.occurredAt.toISOString(),
  })),
  sourceCounts:{
   assessments:snapshots.length,
   actions:actions.length,events:events.length,
  },
  caps:{assessments:200,actions:500,events:2000},
 });
 if(!verifyTrendReport(report,organizationId).valid)
  throw Error("TREND_OUTPUT_INTEGRITY_FAILED");
 return report;
}
