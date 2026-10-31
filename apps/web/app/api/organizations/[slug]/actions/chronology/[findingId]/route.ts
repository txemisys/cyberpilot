import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../../lib/finding-review-data";
import {buildControlChronology,exportControlChronologyText} from "../../../../../../../lib/control-chronology";

/** Download a factual chronology without exposing raw evidence or credentials. */
export async function GET(_request:Request,{params}:{params:Promise<{slug:string;findingId:string}>}){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)return new Response("Finding not found",{
  status:404,headers:{"Cache-Control":"private, no-store"},
 });
 const chronology=buildControlChronology(finding);
 const output=exportControlChronologyText(finding,chronology);
 return new Response(output,{headers:{
  "Content-Type":"text/plain; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-control-chronology.txt"',
  "Cache-Control":"private, no-store",
  "X-Content-Type-Options":"nosniff",
 }});
}
