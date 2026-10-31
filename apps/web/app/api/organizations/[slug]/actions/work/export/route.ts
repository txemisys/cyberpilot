import { db } from "@cyberpilot/database";
import { NextRequest,NextResponse } from "next/server";
import { requireOrganizationAccess } from "../../../../../../../lib/organizations";
import { parseWorkFilter,deriveWorkDue,WorkInputError } from "../../../../../../../lib/remediation-work-input";
import { workWhere } from "../../../../../../../lib/remediation-work-store";
import { buildWorkCsv,exportFileName } from "../../../../../../../lib/remediation-work-export";
type Route={params:Promise<{slug:string}>};
const headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"};
export async function GET(request:NextRequest,{params}:Route){
  try{
    const {slug}=await params;
    const {membership}=await requireOrganizationAccess(slug);
    const now=new Date();
    const filter=parseWorkFilter(Object.fromEntries(request.nextUrl.searchParams));
    const organizationId=membership.organization.id;
    const where=workWhere(organizationId,filter,now);
    const [count,rows]=await db.$transaction([
      db.remediationWorkItem.count({where}),
      db.remediationWorkItem.findMany({
        where,take:1001,
        select:{
          id:true,title:true,description:true,status:true,priority:true,
          assignee:{select:{name:true,email:true}},dueAt:true,
          remediation:{select:{title:true,status:true}},
          finding:{select:{title:true,severity:true,status:true}},
          createdAt:true,updatedAt:true,completedAt:true,revision:true
        },orderBy:[{updatedAt:"desc"},{id:"asc"}]
      })
    ],{isolationLevel:"RepeatableRead"});
    if(count>1000||rows.length!==count)
      return NextResponse.json({
        error:"Export limited to 1,000 work items. Narrow filters and retry.",
        matched:count,limit:1000
      },{status:413,headers});
    const csv=buildWorkCsv(rows.map(row=>({
      ...row,dueState:deriveWorkDue(now,row.dueAt,row.status)
    })));
    return new NextResponse(csv,{
      headers:{
        ...headers,"Content-Type":"text/csv; charset=utf-8",
        "Content-Disposition":`attachment; filename="${exportFileName(slug,now)}"`
      }
    });
  }catch(error){
    if(error instanceof WorkInputError)return NextResponse.json(
      {error:error.message},{status:400,headers}
    );
    console.error("Operational work export failed",error instanceof Error?error.message:"unknown");
    return NextResponse.json({error:"Unable to export work items."},{status:500,headers});
  }
}
