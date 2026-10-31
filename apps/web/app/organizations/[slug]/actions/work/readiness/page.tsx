import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {canManageWork} from "../../../../../../lib/remediation-work-input";
import WorkReadinessBoard from "./work-readiness-board";
type Props={params:Promise<{slug:string}>};
export default async function WorkReadinessPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Remediation operations</p>
  <h1 className="dashboard-title">Operational closure readiness</h1>
  <p className="lede">{membership.organization.name} · Assess whether recorded
   task coordination is ready for human review without changing findings.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Return to work coordination</Link></p>
  <WorkReadinessBoard slug={slug} canManage={canManageWork(membership.role)}/>
 </section></main>;
}
