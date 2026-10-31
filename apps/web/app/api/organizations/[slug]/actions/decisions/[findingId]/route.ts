import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../../lib/finding-review-data";
import {buildManagementDecisions,managementDecisionsText} from "../../../../../../../lib/management-decision-board";

/** Single-finding decision briefing, scoped to an authorized organization. */
export async function GET(
 _request:Request,
 {params}:{params:Promise<{slug:string;findingId:string}>},
){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)return new Response("Finding not found",{
  status:404,headers:{"Cache-Control":"private, no-store"},
 });
 const decisions=buildManagementDecisions(finding);
 const briefing=[
  "Finding: "+finding.title,
  "Severity: "+finding.severity,
  "Finding status: "+finding.status,
  "Finding last observed: "+finding.lastSeenAt.toISOString(),
  "This briefing is an operational review snapshot, not an approval.",
  "",
  managementDecisionsText(decisions),
 ].join("\n");
 return new Response(briefing,{headers:{
  "Content-Type":"text/plain; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-finding-decision-agenda.txt"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
