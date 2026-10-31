import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import WorkInboxBoard from "./work-inbox-board";

type Props={params:Promise<{slug:string}>};
export default async function WorkInboxPage({params}:Props){
 const {slug}=await params;
 const {session,membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Remediation coordination</p>
  <h1 className="dashboard-title">My work and handoffs</h1>
  <p className="lede">{membership.organization.name} · Review recorded
   assignments and responsibility requests in one prioritized queue.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Back to work management</Link></p>
  <WorkInboxBoard slug={slug} currentUserId={session.user.id}/>
 </section></main>;
}
