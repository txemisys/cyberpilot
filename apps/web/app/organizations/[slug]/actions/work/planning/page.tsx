import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {canManageWork} from "../../../../../../lib/remediation-work-input";
import WorkPlanningBoard from "./work-planning-board";
type Props={params:Promise<{slug:string}>};
export default async function AssignmentPlanningPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Remediation operations</p>
  <h1 className="dashboard-title">Assignment and workload planning</h1>
  <p className="lede">{membership.organization.name} · Explore a transparent
   capacity scenario without modifying live security controls.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Return to work coordination</Link></p>
  {canManageWork(membership.role)?<WorkPlanningBoard slug={slug}/>:<section className="panel">
   <h2>Management access required</h2>
   <p>Assignment planning and bulk changes are available to organization owners
    and administrators. The standard work board remains available for review.</p>
  </section>}
 </section></main>;
}
