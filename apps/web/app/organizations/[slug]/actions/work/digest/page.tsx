import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import WorkDigestBoard from "./work-digest-board";
type Props={params:Promise<{slug:string}>};
export default async function WorkDigestPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Operational coordination</p>
  <h1 className="dashboard-title">Remediation work digest</h1>
  <p className="lede">{membership.organization.name} · Examine a current
   snapshot of recorded task blockers, deadlines and supporting work.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Return to work coordination</Link></p>
  <WorkDigestBoard slug={slug}/>
 </section></main>;
}
