import { db } from "@cyberpilot/database";
import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../../../lib/organizations";
import { checklistId,ChecklistError } from "../../../../../../../../../lib/work-checklist-policy";
import { buildChecklistCsv,checklistFilename } from "../../../../../../../../../lib/work-checklist-export";
type Route={params:Promise<{slug:string;workId:string}>};
const safeHeaders={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(_request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const organizationId=membership.organization.id;
  const id=checklistId(workId);
  const parent=await db.remediationWorkItem.findFirst({
   where:{id,organizationId},select:{id:true}
  });
  if(!parent)throw new ChecklistError("NOT_FOUND","Work item not found.");
  const rows=await db.workChecklistEntry.findMany({
   where:{organizationId,workItemId:id},
   select:{
    position:true,title:true,description:true,completedAt:true,
    completedBy:{select:{name:true,email:true}},
    createdAt:true,updatedAt:true
   },
   orderBy:[{position:"asc"},{id:"asc"}],take:101
  });
  if(rows.length>100)throw new ChecklistError("CAPACITY","Checklist export exceeds 100 entries.");
  const body=buildChecklistCsv(rows);
  return new NextResponse(body,{
   status:200,headers:{
    ...safeHeaders,"Content-Type":"text/csv; charset=utf-8",
    "Content-Disposition":`attachment; filename="${checklistFilename(id)}"`
   }
  });
 }catch(error){
  if(error instanceof ChecklistError){
   const status={INVALID:400,FORBIDDEN:403,NOT_FOUND:404,CONFLICT:409,CAPACITY:413}[error.code];
   return NextResponse.json({error:error.message},{status,headers:safeHeaders});
  }
  console.error("Checklist export error",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Cannot export work checklist"},{status:500,headers:safeHeaders});
 }
}
