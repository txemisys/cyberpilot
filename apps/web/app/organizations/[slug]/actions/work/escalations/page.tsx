import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {canManageWork} from "../../../../../../lib/remediation-work-input";
import WorkEscalationBoard from "./work-escalation-board";
type Props={params:Promise<{slug:string}>};
export default async function WorkEscalationsPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Operational remediation</p>
  <h1 className="dashboard-title">Work escalation and attention review</h1>
  <p className="lede">{membership.organization.name} · Identify stalled, blocked,
   overdue and unassigned work using recorded operational facts.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Return to work coordination</Link></p>
  <WorkEscalationBoard slug={slug} canManage={canManageWork(membership.role)}/>
 </section></main>;
}
