import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { readIncidentSituation,readIncidentSituationIndex,
  type SituationSelection } from "./incident-situation-service";
import { assessIncidentAssurance,DEFAULT_ASSURANCE_POLICY,
  validateAssurancePolicy,type AssurancePolicy }
  from "./incident-assurance-domain";
import { prepareAssuranceWorkPacket,buildAssuranceEscalationPlan,
  exportAssuranceDossier } from "./incident-assurance-operations";
import { runOrganizationTabletop,
  type TabletopRequest } from "./incident-tabletop-service";
export class AssuranceServiceError extends Error {
  constructor(public readonly code:string){super(code);}
}
function fail(code:string):never{throw new AssuranceServiceError(code);}
const ident=(value:unknown):value is string=>typeof value==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(value);
async function authorize(actor:IncidentActor){
  if(!ident(actor.organizationId)||!ident(actor.userId)||
      !["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("ASSURANCE_REVIEW_ROLE_DENIED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)
    fail("ASSURANCE_MEMBERSHIP_REVOKED");
}
export type AssuranceRequest = {
  situation:SituationSelection;
  policy?:AssurancePolicy;
  tabletop?:TabletopRequest|null;
  format?:"JSON"|"CSV"|"MARKDOWN";
};
export async function reviewIncidentAssurance(
  actor:IncidentActor,request:AssuranceRequest,
){
  await authorize(actor);
  if(!request||typeof request!=="object"||
      !request.situation||typeof request.situation!=="object")
    fail("ASSURANCE_REQUEST_INVALID");
  const policy=request.policy??DEFAULT_ASSURANCE_POLICY;
  if(validateAssurancePolicy(policy).length)
    fail("ASSURANCE_POLICY_INVALID");
  if(request.tabletop &&
      request.tabletop.type!==undefined &&
      !ident(request.tabletop.scenarioId))
    fail("ASSURANCE_TABLETOP_SCENARIO_INVALID");
  if(request.format!==undefined&&
      !["JSON","CSV","MARKDOWN"].includes(request.format))
    fail("ASSURANCE_FORMAT_INVALID");
  const situation=await readIncidentSituation(actor,request.situation);
  // Tabletop is deterministic, in-memory and cannot certify live provider
  // action; it must match the same playbook and organization.
  let tabletop:Awaited<ReturnType<typeof runOrganizationTabletop>>|null=null;
  if(request.tabletop){
    if(request.tabletop.type!==situation.situation.playbookType)
      fail("ASSURANCE_TABLETOP_PLAYBOOK_MISMATCH");
    tabletop=await runOrganizationTabletop(actor,request.tabletop);
    if(tabletop.organizationId!==actor.organizationId)
      fail("ASSURANCE_TABLETOP_TENANT_MISMATCH");
  }
  const evaluatedAt=new Date().toISOString();
  const report=assessIncidentAssurance({
    situation:situation.situation,
    tabletop:tabletop?.debrief??null,evaluatedAt,policy,
  });
  const packet=prepareAssuranceWorkPacket(report);
  const escalation=buildAssuranceEscalationPlan(report);
  const artifact=request.format?
    exportAssuranceDossier(report,request.format):null;
  return{
    schema:"cyberpilot.incident.assurance.read.v1" as const,
    organizationId:actor.organizationId,
    incidentId:situation.incidentId,
    incidentRevision:situation.incidentRevision,
    policy,report,packet,escalation,
    sourceFailures:situation.sourceFailures,
    simulation:tabletop?{
      scenarioId:tabletop.scenarioId,
      debrief:tabletop.debrief,
      simulatedDecisionCount:tabletop.exercise.events.length,
      realProviderActions:0 as const,
    }:null,
    artifact,persistedReport:false as const,
    externalProviderCalls:0 as const,externalWrites:0 as const,
    signoffGranted:false as const,
  };
}
export async function readAssurancePolicyCatalog(
  actor:IncidentActor,
){
  await authorize(actor);
  return{
    schema:"cyberpilot.incident.assurance.policies.v1" as const,
    organizationId:actor.organizationId,
    defaultPolicy:DEFAULT_ASSURANCE_POLICY,
    templateOverrides:{
      strict:{
        ...DEFAULT_ASSURANCE_POLICY,id:"strict-offline-assurance-v1",
        requireFullSourceScope:true,maxUnknownSourceCount:0,
        maximumPendingSteps:0,minimumTabletopCoveragePercent:100,
        reviewIntervalHours:4,
      },
      investigation:{
        ...DEFAULT_ASSURANCE_POLICY,id:"investigation-offline-assurance-v1",
        requireTabletopForCritical:false,
        maxUnknownSourceCount:3,
        maximumPendingSteps:200,
        minimumTabletopCoveragePercent:60,
        reviewIntervalHours:8,
      },
    },
    providerProofAvailable:false as const,
    actualTenantConsentGranted:false as const,
    policyChangesPersisted:false as const,
  };
}
export async function collectAssuranceIndex(
  actor:IncidentActor,input:{
    offset?:number;limit?:number;
  }={},
){
  await authorize(actor);
  const response=await readIncidentSituationIndex(actor,
    input.offset??0,input.limit??30);
  return{
    schema:"cyberpilot.incident.assurance.index.v1" as const,
    organizationId:actor.organizationId,
    incidents:response.cases,
    total:response.total,
    nextOffset:response.nextOffset,
    policyId:DEFAULT_ASSURANCE_POLICY.id,
    sourceCoverageStatus:"CASE_ONLY" as const,
    securityCertified:false as const,
    externalActions:0 as const,
  };
}
export async function reviewAssuranceMultiCase(
  actor:IncidentActor,ids:string[],
){
  await authorize(actor);
  if(!Array.isArray(ids)||ids.length>20||
      ids.some(x=>!ident(x)))
    fail("ASSURANCE_MULTI_CASE_SELECTION_INVALID");
  const unique=[...new Set(ids)];
  const summaries=[];
  for(const id of unique){
    const result=await reviewIncidentAssurance(actor,{
      situation:{
        incidentId:id,consistency:"FAIL_CLOSED",
        evidence:null,assets:null,remediation:null,
      },
    });
    summaries.push({
      incidentId:id,revision:result.incidentRevision,
      status:result.report.status,
      riskBand:result.report.riskBand,
      unknownControls:result.report.unknownControls,
      criticalFailures:result.report.criticalFailures,
      reportDigest:result.report.integrityDigest,
      dataScope:"CASE_ONLY",
    });
  }
  return{
    schema:"cyberpilot.incident.assurance.multi-case.v1" as const,
    organizationId:actor.organizationId,
    summaries:summaries.sort((a,b)=>
      b.criticalFailures-a.criticalFailures ||
      b.unknownControls-a.unknownControls ||
      a.incidentId.localeCompare(b.incidentId)),
    completeProviderPicture:false as const,
    providerWrites:0 as const,
  };
}
