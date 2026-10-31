import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../../lib/finding-review-data";
import {buildAuditPacket,auditPacketText} from "../../../../../../../lib/audit-preparation";
export async function GET(_request:Request,{params}:{params:Promise<{slug:string;findingId:string}>}){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)return new Response("Finding not found",{
  status:404,headers:{"Cache-Control":"private, no-store"},
 });
 const packet=buildAuditPacket(finding);
 return new Response(auditPacketText(packet),{headers:{
  "Content-Type":"text/plain; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-audit-packet.txt"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
