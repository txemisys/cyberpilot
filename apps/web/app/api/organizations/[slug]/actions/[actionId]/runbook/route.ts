import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {normalizeRunbookSteps,runbookPlainText} from "../../../../../../../lib/remediation-runbook";

/**
 * Download a plain-text operational runbook for an authorized organization.
 * Excludes raw evidence, user identities, integration secrets, and audit metadata.
 */
export async function GET(_request:Request,{params}:{params:Promise<{slug:string;actionId:string}>}){
 const {slug,actionId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const action=await db.remediation.findFirst({
  where:{organizationId,id:actionId},
  select:{
   id:true,title:true,summary:true,status:true,mode:true,steps:true,verification:true,
   createdAt:true,approvedAt:true,startedAt:true,completedAt:true,verifiedAt:true,
   finding:{select:{title:true,status:true,severity:true}},
  },
 });
 if(!action)return new Response("Action not found",{status:404,headers:{"Cache-Control":"private, no-store"}});
 const progress=await db.guidedRemediationStep.findMany({
  where:{organizationId,remediationId:action.id},select:{stepIndex:true},
 });
 const text=runbookPlainText({
  id:action.id,title:action.title,summary:action.summary,status:action.status,mode:action.mode,
  severity:action.finding.severity,findingTitle:action.finding.title,
  findingStatus:action.finding.status,
  instructions:normalizeRunbookSteps(action.steps),
  verification:normalizeRunbookSteps(action.verification),
  acknowledgedSteps:new Set(progress.map(x=>x.stepIndex)),
  createdAt:action.createdAt,approvedAt:action.approvedAt,startedAt:action.startedAt,
  completedAt:action.completedAt,verifiedAt:action.verifiedAt,
 });
 return new Response(text,{
  headers:{
   "Content-Type":"text/plain; charset=utf-8",
   "Content-Disposition":'attachment; filename="cyberpilot-remediation-runbook.txt"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
