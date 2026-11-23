import { db } from "@cyberpilot/database";
import type { IncidentActor } from "./incident-case-service";
import { INCIDENT_TYPES, getIncidentPlaybook,
  type IncidentType } from "./incident-playbook-catalog";
import { generateTabletopScenario, type TabletopFault,
  type TabletopMove } from "./incident-tabletop-domain";
import { planTabletopExercise, executeDeterministicTabletop,
  exportTabletopReplay } from "./incident-tabletop-operations";
export class TabletopServiceError extends Error {
  constructor(public readonly code:string){super(code);}
}
function fail(code:string):never{throw new TabletopServiceError(code);}
const ident=(x:unknown):x is string=>typeof x==="string"&&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(x);
const iso=(x:unknown):x is string=>typeof x==="string"&&
  Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x;
async function authorize(actor:IncidentActor){
  if(!ident(actor.organizationId)||!ident(actor.userId)||
      !["OWNER","ADMIN","AUDITOR"].includes(actor.role))
    fail("TABLETOP_REVIEWER_ROLE_REQUIRED");
  const member=await db.membership.findFirst({
    where:{organizationId:actor.organizationId,userId:actor.userId},
    select:{role:true},
  });
  if(!member||member.role!==actor.role)fail("TABLETOP_MEMBERSHIP_REVOKED");
}
export type TabletopRequest={
  scenarioId:string;type:IncidentType;title:string;
  seed:number;at:string;faultCount:number;
  additionalFaults:TabletopFault[];
  moves:TabletopMove[];
  reviewedAt:string;
  format?:"JSON"|"CSV"|"MARKDOWN";
};
function validate(request:TabletopRequest){
  if(!ident(request.scenarioId)||!INCIDENT_TYPES.includes(request.type)||
      typeof request.title!=="string"||
      request.title.length<5||request.title.length>180||
      !Number.isSafeInteger(request.seed)||request.seed<0||
      request.seed>0xffffffff||
      !Number.isSafeInteger(request.faultCount)||
      request.faultCount<1||request.faultCount>8||
      !iso(request.at)||!iso(request.reviewedAt)||
      request.reviewedAt<request.at||
      !Array.isArray(request.additionalFaults)||
      request.additionalFaults.length>8||
      !Array.isArray(request.moves)||request.moves.length>300)
    fail("TABLETOP_REQUEST_INVALID");
}
export async function runOrganizationTabletop(
  actor:IncidentActor,request:TabletopRequest,
){
  await authorize(actor);
  validate(request);
  const scenario=generateTabletopScenario({
    id:request.scenarioId,organizationId:actor.organizationId,
    type:request.type,title:request.title,seed:request.seed,
    at:request.at,faultCount:request.faultCount,
    additionalFaults:request.additionalFaults,
  });
  const plan=planTabletopExercise(scenario);
  const result=executeDeterministicTabletop(scenario,
    request.moves,request.reviewedAt);
  const artifact=request.format?
    exportTabletopReplay(result,request.format):null;
  return{
    schema:"cyberpilot.incident.tabletop.run.v1" as const,
    organizationId:actor.organizationId,
    scenario,plan,...result,artifact,
    persisted:false as const,
    tenantRemotePermissionsUsed:false as const,
    incidentCasesMutated:0 as const,providerWrites:0 as const,
    independentSecurityBenefitProven:false as const,
  };
}
export async function readTabletopCatalog(actor:IncidentActor){
  await authorize(actor);
  return{
    schema:"cyberpilot.incident.tabletop.catalog.v1" as const,
    organizationId:actor.organizationId,
    playbooks:INCIDENT_TYPES.map(type=>{
      const book=getIncidentPlaybook(type);
      return{
        id:type,title:book.title,severity:book.severity,
        description:book.description,version:book.version,
        stages:book.steps.length,
        highImpact:book.steps.filter(x=>x.requiresApproval).length,
        expectedRoles:[...new Set(book.steps.map(x=>x.suggestedOwner))],
        immediateSafety:book.immediateSafety,
        escalation:book.escalation,
        externalOperationsAllowed:false as const,
      };
    }),
    scenarioExecutionMode:"MEMORY_ONLY_DETERMINISTIC" as const,
    availableFaultCount:20,
    actualProviderProofAvailable:false as const,
  };
}
export async function runTabletopScenarioMatrix(
  actor:IncidentActor,seed:number,at:string,
){
  await authorize(actor);
  if(!Number.isSafeInteger(seed)||seed<0||seed>0xffffffff||!iso(at))
    fail("TABLETOP_MATRIX_REQUEST_INVALID");
  const reports=INCIDENT_TYPES.map((type,index)=>{
    const scenario=generateTabletopScenario({
      id:"matrix-"+String(index+1).padStart(2,"0")+"-scenario",
      organizationId:actor.organizationId,
      type,title:"LAB scenario for "+type,
      seed:(seed+index)>>>0,at,faultCount:5,
    });
    const plan=planTabletopExercise(scenario);
    const replay=executeDeterministicTabletop(scenario,[],at);
    return{
      type,scenarioId:scenario.id,seed:scenario.scenarioSeed,
      faults:scenario.injectedFaults,injectCount:plan.injects.length,
      highImpactSteps:plan.walkthrough.filter(x=>x.approvalRequired).length,
      blockedWrites:replay.exercise.externalProviderWrites===0,
      unattendedExerciseComplete:false,
      stageCoveragePercent:replay.debrief.stageCoveragePercent,
      noTenantNeeded:true as const,
    };
  });
  return{
    schema:"cyberpilot.incident.tabletop.matrix.v1" as const,
    organizationId:actor.organizationId,seed,at,reports,
    allPlaybooksCovered:reports.length===5,
    customerSecurityOutcomeVerified:false as const,
    providerWrites:0 as const,
  };
}
export async function examineTabletopSafety(
  actor:IncidentActor,input:{
    type:IncidentType;seed:number;scenarioId:string;at:string;
    faultCount:number;
  },
){
  await authorize(actor);
  if(!INCIDENT_TYPES.includes(input.type)||!ident(input.scenarioId)||
      !Number.isSafeInteger(input.seed)||input.seed<0||
      input.seed>0xffffffff||!iso(input.at)||
      !Number.isSafeInteger(input.faultCount)||
      input.faultCount<1||input.faultCount>8)
    fail("TABLETOP_PREFLIGHT_INVALID");
  const scenario=generateTabletopScenario({
    id:input.scenarioId,organizationId:actor.organizationId,
    type:input.type,title:"Safety preparation "+input.type,
    seed:input.seed,at:input.at,faultCount:input.faultCount,
  });
  const plan=planTabletopExercise(scenario);
  return{
    schema:"cyberpilot.incident.tabletop.preflight.v1" as const,
    organizationId:actor.organizationId,
    scenarioId:scenario.id,
    risk:scenario.injectedRisk,
    incidentType:scenario.incidentType,
    authorizationNotGranted:true as const,
    scenarios:plan.injects.map(x=>({
      fault:x.fault,expectedGuardrail:x.expectedGuardrail,
      requiredFacilitatorIntervention:true as const,
    })),
    stepLimit:plan.walkthrough.length,
    highRiskSteps:plan.walkthrough.filter(x=>x.approvalRequired)
      .map(x=>x.stepId),
    noCustomerTenantRequired:true as const,
    externalProviderWrites:0 as const,
  };
}
