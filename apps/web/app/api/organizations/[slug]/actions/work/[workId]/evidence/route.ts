import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {EvidenceLinkError} from "../../../../../../../../lib/work-evidence-policy";
import {findEvidenceCandidates,listWorkEvidence,mutateWorkEvidence} from "../../../../../../../../lib/work-evidence-store";
type Route={params:Promise<{slug:string;workId:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
function failure(e:unknown){
 if(e instanceof EvidenceLinkError){
  const status={INVALID:400,FORBIDDEN:403,NOT_FOUND:404,CONFLICT:409,CAPACITY:413}[e.code];
  return NextResponse.json({error:e.message,code:e.code},{status,headers});
 }
 if(e instanceof SyntaxError)return NextResponse.json({error:"Invalid JSON"},{status:400,headers});
 console.error("Evidence link operation",e instanceof Error?e.message:"unknown");
 return NextResponse.json({error:"Evidence link operation failed"},{status:500,headers});
}
async function scope(slug:string){
 const {session,membership}=await requireOrganizationAccess(slug);
 return {organizationId:membership.organization.id,userId:session.user.id,role:membership.role};
}
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const context=await scope(slug);
  const query=request.nextUrl.searchParams;
  if(query.get("view")==="candidates")
   return NextResponse.json(await findEvidenceCandidates(context,workId,query.get("search")),{headers});
  return NextResponse.json(await listWorkEvidence(context,workId),{headers});
 }catch(e){return failure(e);}
}
export async function POST(request:NextRequest,{params}:Route){
 try{
  const {slug,workId}=await params;
  const context=await scope(slug);
  const body:unknown=await request.json();
  return NextResponse.json(await mutateWorkEvidence(context,workId,body),{headers});
 }catch(e){return failure(e);}
}
