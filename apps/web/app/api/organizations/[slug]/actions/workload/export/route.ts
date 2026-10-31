import {db} from "@cyberpilot/database";
import {requireOrganizationAccess} from "../../../../../../../lib/organizations";
import {buildMonthlyWorkload,createWorkloadCsv} from "../../../../../../../lib/remediation-workload";

/** Tenant-scoped export of recorded monthly operational activity. */
export async function GET(_request:Request,{params}:{params:Promise<{slug:string}>}){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const total=await db.remediation.count({where:{organizationId}});
 if(total>2000){
  return new Response("More than 2000 actions. Use the filtered action export instead.",{
   status:422,headers:{"Cache-Control":"private, no-store"},
  });
 }
 const actions=await db.remediation.findMany({
  where:{organizationId},orderBy:[{createdAt:"desc"},{id:"asc"}],take:2000,
  select:{createdAt:true,verifiedAt:true,status:true},
 });
 const months=buildMonthlyWorkload(actions);
 return new Response(createWorkloadCsv(months),{headers:{
  "Content-Type":"text/csv; charset=utf-8",
  "Content-Disposition":'attachment; filename="cyberpilot-remediation-monthly.csv"',
  "Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff",
 }});
}
