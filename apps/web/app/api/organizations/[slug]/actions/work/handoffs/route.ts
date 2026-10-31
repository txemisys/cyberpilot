import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {HandoffError} from "../../../../../../../lib/work-handoff-policy";
import {createHandoff,decideHandoff,listHandoffs} from "../../../../../../../lib/work-handoff-store";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function fail(e:unknown){
 if(e instanceof HandoffError){
  const status={INVALID:400,FORBIDDEN:403,NOT_FOUND:404,CONFLICT:409,CAPACITY:413}[e.code];
  return NextResponse.json({error:e.message,code:e.code},{status,headers});
 }
 if(e instanceof SyntaxError)return NextResponse.json({error:"Invalid JSON"},{status:400,headers});
 console.error("Work handoff API",e instanceof Error?e.message:"unknown");
 return NextResponse.json({error:"Handoff operation failed"},{status:500,headers});
}
async function context(slug:string){
 const {session,membership}=await requireOrganizationAccess(slug);
 return {organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
}
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;const scope=await context(slug);
  const q=request.nextUrl.searchParams.get("view");
  const view=q==="INBOX"||q==="PENDING"?q:"ALL";
  return NextResponse.json(await listHandoffs(scope,view),{headers});
 }catch(e){return fail(e);}
}
export async function POST(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;const scope=await context(slug);
  const body:unknown=await request.json();
  return NextResponse.json({handoff:await createHandoff(scope,body)},{status:201,headers});
 }catch(e){return fail(e);}
}
export async function PATCH(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;const scope=await context(slug);
  const body:unknown=await request.json();
  return NextResponse.json({handoff:await decideHandoff(scope,body)},{headers});
 }catch(e){return fail(e);}
}
