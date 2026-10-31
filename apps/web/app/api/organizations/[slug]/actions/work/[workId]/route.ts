import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { commentWorkItem,getWorkItem,updateWorkItem } from "../../../../../../../lib/remediation-work-store";
import { parseRevision,parseWorkId,WorkInputError } from "../../../../../../../lib/remediation-work-input";

type Route={params:Promise<{slug:string;workId:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function failure(error:unknown){
  if(error instanceof WorkInputError){
    const status={INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code];
    return NextResponse.json({error:error.message,code:error.code},{status,headers});
  }
  console.error("Work detail API failure",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Work operation failed."},{status:500,headers});
}
async function context(slug:string){
  const {session,membership}=await requireOrganizationAccess(slug);
  return {organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
}
export async function GET(_request:NextRequest,{params}:Route){
  try{
    const {slug,workId}=await params;
    const scope=await context(slug);
    return NextResponse.json({item:await getWorkItem(scope,parseWorkId(workId))},{headers});
  }catch(error){return failure(error);}
}
export async function PATCH(request:NextRequest,{params}:Route){
  try{
    const {slug,workId}=await params;
    const scope=await context(slug);
    const body:unknown=await request.json();
    if(!body||typeof body!=="object"||Array.isArray(body))
      throw new WorkInputError("INVALID","Expected an object.");
    const value=body as Record<string,unknown>;
    const revision=parseRevision(value.revision);
    if(!value.value||Object.keys(value).some(key=>key!=="revision"&&key!=="value"))
      throw new WorkInputError("INVALID","Expected revision and value.");
    const item=await updateWorkItem(scope,parseWorkId(workId),revision,value.value);
    return NextResponse.json({item},{headers});
  }catch(error){return failure(error);}
}
export async function POST(request:NextRequest,{params}:Route){
  try{
    const {slug,workId}=await params;
    const scope=await context(slug);
    const body:unknown=await request.json();
    if(!body||typeof body!=="object"||Array.isArray(body))
      throw new WorkInputError("INVALID","Expected a comment object.");
    const value=body as Record<string,unknown>;
    if(Object.keys(value).some(key=>key!=="comment"))
      throw new WorkInputError("INVALID","Unexpected comment field.");
    const event=await commentWorkItem(scope,parseWorkId(workId),value.comment);
    return NextResponse.json({event},{status:201,headers});
  }catch(error){return failure(error);}
}
