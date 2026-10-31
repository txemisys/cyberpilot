import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { checklistId,ChecklistError } from "../../../../../../../lib/work-checklist-policy";
import { readChecklist,mutateChecklist } from "../../../../../../../lib/work-checklist-store";

type Route={params:Promise<{slug:string;workId:string}>};
const safeHeaders={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function errorResponse(error:unknown){
 if(error instanceof ChecklistError){
  const status={INVALID:400,FORBIDDEN:403,NOT_FOUND:404,CONFLICT:409,CAPACITY:413}[error.code];
  return NextResponse.json({error:error.message,code:error.code},{status,headers:safeHeaders});
 }
 if(error instanceof SyntaxError)
  return NextResponse.json({error:"Invalid JSON request"},{status:400,headers:safeHeaders});
 console.error("Checklist request error",error instanceof Error?error.message:"unknown");
 return NextResponse.json({error:"Checklist operation failed"},{status:500,headers:safeHeaders});
}
async function context(slug:string){
 const {session,membership}=await requireOrganizationAccess(slug);
 return {organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
}
export async function GET(_request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const scope=await context(slug);
  const model=await readChecklist(scope,checklistId(workId));
  return NextResponse.json(model,{headers:safeHeaders});
 }catch(error){return errorResponse(error);}
}
export async function POST(request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const scope=await context(slug);
  const id=checklistId(workId);
  const body:unknown=await request.json();
  if(!body||typeof body!=="object"||Array.isArray(body))
   throw new ChecklistError("INVALID","Expected checklist operation.");
  const data=body as Record<string,unknown>;
  if(data.workItemId!==undefined&&data.workItemId!==id)
   throw new ChecklistError("INVALID","Work item path and body disagree.");
  const result=await mutateChecklist(scope,{...data,workItemId:id});
  return NextResponse.json({result},{status:200,headers:safeHeaders});
 }catch(error){return errorResponse(error);}
}
