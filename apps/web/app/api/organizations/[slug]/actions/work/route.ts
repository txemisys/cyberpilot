import { NextRequest, NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import {
  createWorkItem,listWorkItems,organizationAssignees,workSummaryForOrganization,
  untrackedRemediations
} from "../../../../../../lib/remediation-work-store";
import { WorkInputError } from "../../../../../../lib/remediation-work-input";

type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};

function errorResponse(error:unknown){
  if(error instanceof WorkInputError){
    const code={INVALID:400,FORBIDDEN:403,MISSING:404,CONFLICT:409}[error.code];
    return NextResponse.json({error:error.message,code:error.code},{status:code,headers});
  }
  console.error("Work API failure",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Work operation failed."},{status:500,headers});
}
async function context(slug:string){
  const {session,membership}=await requireOrganizationAccess(slug);
  return {organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
}
export async function GET(request:NextRequest,{params}:Route){
  try{
    const {slug}=await params;
    const scope=await context(slug);
    const query=Object.fromEntries(request.nextUrl.searchParams);
    if(query.meta==="assignees")return NextResponse.json(
      {assignees:await organizationAssignees(scope)},{headers}
    );
    if(query.meta==="untracked")return NextResponse.json(
      {remediations:await untrackedRemediations(scope)},{headers}
    );
    if(query.meta==="summary")return NextResponse.json(
      {summary:await workSummaryForOrganization(scope)},{headers}
    );
    return NextResponse.json(await listWorkItems(scope,query),{headers});
  }catch(error){return errorResponse(error);}
}
export async function POST(request:NextRequest,{params}:Route){
  try{
    const {slug}=await params;
    const scope=await context(slug);
    const body:unknown=await request.json();
    const created=await createWorkItem(scope,body);
    return NextResponse.json({item:created},{status:201,headers});
  }catch(error){
    if(error instanceof SyntaxError)return NextResponse.json(
      {error:"Malformed JSON."},{status:400,headers}
    );
    return errorResponse(error);
  }
}
