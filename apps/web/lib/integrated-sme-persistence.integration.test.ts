import {randomUUID} from "node:crypto";
import {beforeAll,afterAll,describe,expect,it} from "vitest";
import {db} from "@cyberpilot/database";
import {collectIntegratedRiskDigest} from "./integrated-risk-service";
import {createIntegratedAction,readIntegratedActions,
  updateIntegratedAction} from "./integrated-action-service";
import {collectExecutiveCockpit} from "./integrated-executive-cockpit-service";

describe.skipIf(!process.env.DATABASE_URL)(
  "integrated offline SME PostgreSQL workflows",()=>{
  const id=randomUUID().slice(0,8);
  const org="int-org-"+id,other="int-foreign-"+id;
  const ownerId="int-owner-"+id,otherId="int-foreign-user-"+id;
  const auditorId="int-auditor-"+id;
  const actor={organizationId:org,userId:ownerId,role:"OWNER" as const};
  const outsider={organizationId:other,userId:otherId,role:"OWNER" as const};
  const auditor={organizationId:org,userId:auditorId,role:"AUDITOR" as const};
  beforeAll(async()=>{
    await db.user.createMany({data:[
      {id:ownerId,name:"Offline owner",
        email:"int-owner-"+id+"@example.invalid"},
      {id:otherId,name:"Foreign owner",
        email:"int-foreign-"+id+"@example.invalid"},
      {id:auditorId,name:"Offline auditor",
        email:"int-auditor-"+id+"@example.invalid"},
    ]});
    await db.organization.createMany({data:[
      {id:org,slug:org,name:"Integrated offline org"},
      {id:other,slug:other,name:"Other offline org"},
    ]});
    await db.membership.createMany({data:[
      {organizationId:org,userId:ownerId,role:"OWNER"},
      {organizationId:other,userId:otherId,role:"OWNER"},
      {organizationId:org,userId:auditorId,role:"AUDITOR"},
    ]});
    await db.securityFinding.create({data:{
      organizationId:org,key:"test-offline-"+id,
      ruleId:"BACKUP_RECOVERY_DRILL",title:"Backup recovery is unverified",
      description:"LAB-only finding without customer tenant",
      severity:"HIGH",status:"OPEN",
    }});
    await db.securityEvidence.create({data:{
      organizationId:org,source:"LAB",domain:"BACKUP",
      controlId:"BACKUP_RECOVERY_DRILL",state:"DECLARED",
      scope:"ORGANIZATION",observedAt:null,
      details:{fixture:true,customerAuthenticated:false},
    }});
  });
  afterAll(async()=>{
    await db.organization.deleteMany({where:{id:{in:[org,other]}}});
    await db.user.deleteMany({
      where:{id:{in:[ownerId,otherId,auditorId]}},
    });
  });
  it("reads actual tenant rows, no false security observations",async()=>{
    const report=await collectIntegratedRiskDigest(actor);
    expect(report.counts.findings).toBe(1);
    expect(report.counts.evidence).toBe(1);
    expect(report.state).toBe("REVIEW_REQUIRED");
    expect(report.controls[0]?.currentState).toBe("DECLARED_ONLY");
    expect(report.historicalV1ScoreModified).toBe(false);
    expect((await collectIntegratedRiskDigest(outsider)).risks)
      .toHaveLength(0);
  });
  it("creates only from persisted risk and keeps idempotency",async()=>{
    const report=await collectIntegratedRiskDigest(actor);
    const key=report.risks[0]!.key;
    const created=await createIntegratedAction(actor,{
      riskKey:key,priority:"HIGH",ownerUserId:ownerId,
      dueAt:null,rationale:"Follow-up with operator",
    });
    expect(created.created).toBe(true);
    expect(created.action.status).toBe("OPEN");
    const replay=await createIntegratedAction(actor,{
      riskKey:key,priority:"LOW",ownerUserId:null,
      dueAt:null,rationale:null,
    });
    expect(replay.created).toBe(false);
    expect(replay.action.actionId).toBe(created.action.actionId);
  });
  it("denies foreign risk and cross-organization assignment",async()=>{
    const key=(await collectIntegratedRiskDigest(actor)).risks[0]!.key;
    await expect(createIntegratedAction(outsider,{
      riskKey:key,priority:"NORMAL",ownerUserId:null,
      dueAt:null,rationale:null,
    })).rejects.toMatchObject({code:"RISK_NOT_PRESENT_OR_NOT_OPEN"});
    await expect(createIntegratedAction(actor,{
      riskKey:key,priority:"NORMAL",ownerUserId:otherId,
      dueAt:null,rationale:null,
    })).rejects.toMatchObject({code:"CROSS_TENANT_ASSIGNEE_DENIED"});
  });
  it("permits auditor reads but no mutation",async()=>{
    const report=await readIntegratedActions(auditor);
    expect(report.actions).toHaveLength(1);
    await expect(updateIntegratedAction(auditor,{
      actionId:report.actions[0]!.actionId,
      expectedRevision:1,kind:"START",
    })).rejects.toMatchObject({code:"ACTION_MANAGER_PERMISSION_REQUIRED"});
  });
  it("persists CAS, audit and rejects stale writes",async()=>{
    const action=(await readIntegratedActions(actor)).actions[0]!;
    const updated=await updateIntegratedAction(actor,{
      actionId:action.actionId,expectedRevision:1,kind:"START",
    });
    expect(updated.action.status).toBe("IN_PROGRESS");
    expect(updated.action.revision).toBe(2);
    const after=await readIntegratedActions(actor);
    expect(after.history).toHaveLength(2);
    expect(after.audits[0]?.valid).toBe(true);
    expect(after.summary.riskActuallyRemediated).toBe(0);
    await expect(updateIntegratedAction(actor,{
      actionId:action.actionId,expectedRevision:1,
      kind:"BLOCK",reason:"Detailed and independently checked blocker",
    })).rejects.toMatchObject({code:"CAS_REVISION_CONFLICT"});
    await expect(updateIntegratedAction(outsider,{
      actionId:action.actionId,expectedRevision:2,kind:"START",
    })).rejects.toMatchObject({code:"ACTION_NOT_FOUND_IN_ORGANIZATION"});
  });
  it("generates executive report over PostgreSQL with no LIVE calls",async()=>{
    const result=await collectExecutiveCockpit(actor);
    expect(result.summary.openRisks).toBe(1);
    expect(result.summary.actionsTotal).toBe(1);
    expect(result.risks[0]?.actionState).toBe("IN_PROGRESS");
    expect(result.summary.auditIssues).toBe(0);
    expect(result.externalProviderCalls).toBe(0);
    expect(result.customerCertificationGranted).toBe(false);
    expect(result.historicalCyberScoreRewritten).toBe(false);
  });
});
