import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { canManageWork } from "../../../../../../lib/remediation-work-input";
import WorkBatchBoard from "./work-batch-board";

type Props = { params: Promise<{ slug: string }> };
export default async function WorkBatchPage({ params }: Props) {
  const { slug } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${slug}/actions/work`;
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Operational remediation</p>
    <h1 className="dashboard-title">Coordinated work updates</h1>
    <p className="lede">{membership.organization.name} · Review changes before committing.</p>
    <p className="action-link"><Link href={base}>Back to work coordination</Link></p>
    {canManageWork(membership.role)
      ? <WorkBatchBoard slug={slug} />
      : <section className="panel">
          <h2>Management permission required</h2>
          <p>Only an organization owner or admin can change task assignments,
            deadlines, work states or priorities in a batch.</p>
          <p>Return to the work board to review current records.</p>
        </section>}
  </section></main>;
}
