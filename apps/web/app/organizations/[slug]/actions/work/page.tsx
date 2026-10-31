import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { canCommentWork,canManageWork } from "../../../../../lib/remediation-work-input";
import WorkBoard from "./work-board";

type Props={params:Promise<{slug:string}>};
export default async function OperationalRemediationWork({params}:Props){
  const {slug}=await params;
  const {session,membership}=await requireOrganizationAccess(slug);
  return <main className="shell">
    <section className="dashboard">
      <p className="eyebrow">CyberPilot · Operational remediation</p>
      <h1 className="dashboard-title">Work coordination</h1>
      <p className="lede">Track assignments, deadlines, blockers and handoffs for {membership.organization.name}.</p>
      <p className="action-link"><Link href={`/organizations/${slug}/actions`}>Return to security actions</Link></p>
      <p className="permission-warning">A completed task is not a verified remediation or a resolved finding.
        Verification requires its own evidence and review workflow.</p>
      <p className="action-link"><Link href={`/organizations/${slug}/actions/work/batch`}>Review and apply batch coordination updates</Link></p>
      <WorkBoard slug={slug} canManage={canManageWork(membership.role)}
        canComment={canCommentWork(membership.role)} currentUserId={session.user.id}/>
    </section>
  </main>;
}
