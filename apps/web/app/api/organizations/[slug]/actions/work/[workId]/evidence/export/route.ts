import {db} from "@cyberpilot/database";
import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../../lib/organizations";
import {EvidenceLinkError,assessLinkedEvidence} from "../../../../../../../../../lib/work-evidence-policy";
type Route={params:Promise<{slug:string;workId:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
const labels=[
 "Evidence ID","Source","Domain","Control","Scope","Evidence state",
 "Observed UTC","Reason for reference","Linked UTC","Detached UTC",
 "Control relationship","Freshness","Review candidate","Warnings"
];
function cell(value:string){
 const safe=/^[\s\u0000-\u001f]*[=+@\-]/.test(value)?"'"+value:value;
 return '"'+safe.replaceAll('"','""')+'"';
}
export async function GET(_request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const organizationId=membership.organization.id;
  const work=await db.remediationWorkItem.findFirst({
   where:{id:workId,organizationId},
   select:{finding:{select:{ruleId:true,key:true,status:true}}}
  });
  if(!work)throw new EvidenceLinkError("NOT_FOUND","Work item not found.");
  const links=await db.workEvidenceLink.findMany({
   where:{organizationId,workItemId:workId},
   select:{
    evidenceId:true,reason:true,linkedAt:true,unlinkedAt:true,
    evidence:{select:{
     id:true,organizationId:true,source:true,domain:true,controlId:true,
     scope:true,state:true,observedAt:true,createdAt:true,updatedAt:true
    }}
   },
   orderBy:[{linkedAt:"desc"},{id:"desc"}],take:101
  });
  if(links.length>100)throw new EvidenceLinkError("CAPACITY","Too many references to export.");
  const now=new Date();
  const lines=links.map(link=>{
   const a=assessLinkedEvidence(link.evidence,work.finding,now);
   return [
    link.evidenceId,link.evidence.source,link.evidence.domain,
    link.evidence.controlId,link.evidence.scope,link.evidence.state,
    link.evidence.observedAt?.toISOString()??"",link.reason,
    link.linkedAt.toISOString(),link.unlinkedAt?.toISOString()??"",
    a.relationship,a.age,a.maySupportReview?"YES":"NO",a.warnings.join("; ")
   ].map(cell).join(",");
  });
  const body=[labels.map(cell).join(","),...lines].join("\r\n")+"\r\n";
  return new NextResponse(body,{status:200,headers:{
   ...headers,"Content-Type":"text/csv; charset=utf-8",
   "Content-Disposition":`attachment; filename="cyberpilot-evidence-references-${workId.replace(/[^a-zA-Z0-9_-]/g,"_")}.csv"`
  }});
 }catch(error){
  if(error instanceof EvidenceLinkError)
   return NextResponse.json({error:error.message},{
    status:error.code==="NOT_FOUND"?404:error.code==="CAPACITY"?413:400,headers
   });
  console.error("Evidence references export",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Unable to export references."},{status:500,headers});
 }
}
