import {db} from "@cyberpilot/database";
import type {Prisma} from "@cyberpilot/database";
import {NextRequest,NextResponse} from "next/server";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {HistoryInputError} from "../../../../../../../lib/work-audit-history";
import {parseFeedFilter,feedSince,countFeedConcerns,groupFeedByWork,serializeFeedDigest} from "../../../../../../../lib/work-organization-activity";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
 try{
  const {slug}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const filter=parseFeedFilter(Object.fromEntries(request.nextUrl.searchParams));
  const where:Prisma.RemediationWorkEventWhereInput={
   organizationId:membership.organization.id,
   occurredAt:{gte:feedSince(new Date(),filter.days)},
   ...(filter.workItemId?{workItemId:filter.workItemId}:{}),
   ...(filter.actorUserId?{actorUserId:filter.actorUserId}:{}),
   ...(filter.kind?{kind:filter.kind as "CREATED"|"UPDATED"|"COMMENTED"|"REOPENED"}:{})
  };
  const [total,rows]=await db.$transaction([
   db.remediationWorkEvent.count({where}),
   db.remediationWorkEvent.findMany({
    where,orderBy:[{occurredAt:"desc"},{id:"desc"}],take:filter.limit,
    select:{
     id:true,workItemId:true,kind:true,actorUserId:true,
     comment:true,occurredAt:true,
     actor:{select:{name:true,email:true}},
     workItem:{select:{title:true,status:true,
      finding:{select:{title:true,status:true,severity:true}}}}
    }
   })
  ],{isolationLevel:"RepeatableRead"});
  return NextResponse.json({
   filter,total,limited:total>rows.length,
   events:serializeFeedDigest(rows),
   concerns:countFeedConcerns(rows),
   byWork:groupFeedByWork(rows),
   disclaimer:"These are coordination and work history records, never verified controls."
  },{headers});
 }catch(error){
  if(error instanceof HistoryInputError)
   return NextResponse.json({error:error.message},{status:400,headers});
  console.error("Organization work feed",error instanceof Error?error.message:"unknown");
  return NextResponse.json({error:"Unable to read organization work activity."},{status:500,headers});
 }
}
