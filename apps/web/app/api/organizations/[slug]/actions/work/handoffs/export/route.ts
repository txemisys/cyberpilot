import {db} from "@cyberpilot/database";
import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../../lib/organizations";
import {serializeHandoffs} from "../../../../../../../../lib/work-handoff-export";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  const organizationId=membership.organization.id;
  const view=request.nextUrl.searchParams.get("view");
  const where={
   organizationId,
   ...(view==="INBOX"?{recipientUserId:session.user.id}:{}),
   ...(view==="PENDING"?{status:"REQUESTED" as const}:{})
  };
  const [count,rows]=await db.$transaction([
   db.workHandoff.count({where}),
   db.workHandoff.findMany({
    where,orderBy:[{requestedAt:"desc"},{id:"desc"}],take:1001,
    select:{
     id:true,workItemId:true,status:true,reason:true,response:true,
     requester:{select:{name:true,email:true}},
     recipient:{select:{name:true,email:true}},
     decider:{select:{name:true,email:true}},
     workItem:{select:{
      title:true,status:true,finding:{select:{title:true,status:true,severity:true}}
     }},
     requestedAt:true,expiresAt:true,decidedAt:true,revision:true
    }
   })
  ],{isolationLevel:"RepeatableRead"});
  if(count>1000||rows.length!==count)
   return NextResponse.json({
    error:"Export exceeds 1,000 handoff records; select a narrower view.",
    matched:count,limit:1000
   },{status:413,headers});
  return new NextResponse(serializeHandoffs(rows),{
   status:200,headers:{
    ...headers,"Content-Type":"text/csv; charset=utf-8",
    "Content-Disposition":`attachment; filename="cyberpilot-handoffs-${slug.replace(/[^a-zA-Z0-9_-]/g,"_")}.csv"`
   }
  });
 }catch(error){
  console.error("Handoff export",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Unable to export handoff history."},{status:500,headers});
 }
}
