import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../../lib/finding-review-data";
import {buildFindingDossier,serializeFindingDossier} from "../../../../../../../lib/finding-dossier";

/** Read-only tenant-authorized download of one documented security finding. */
export async function GET(
 _request:Request,
 {params}:{params:Promise<{slug:string;findingId:string}>},
){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding){
  return new Response("Finding not found",{
   status:404,
   headers:{"Cache-Control":"private, no-store"},
  });
 }
 const dossier=buildFindingDossier(finding);
 const content=serializeFindingDossier(dossier);
 return new Response(content,{
  headers:{
   "Content-Type":"text/plain; charset=utf-8",
   "Content-Disposition":'attachment; filename="cyberpilot-finding-dossier.txt"',
   "Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff",
  },
 });
}
