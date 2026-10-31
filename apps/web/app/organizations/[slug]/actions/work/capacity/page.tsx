import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import WorkCapacityBoard from "./work-capacity-board";
type Props={params:Promise<{slug:string}>};
export default async function WorkCapacityPage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Operational coordination</p>
  <h1 className="dashboard-title">Team work distribution</h1>
  <p className="lede">{membership.organization.name} · Explore recorded task
   distribution and operational attention without estimating employee hours.</p>
  <p className="action-link"><Link href={`/organizations/${slug}/actions/work`}>
   Back to remediation coordination</Link></p>
  <WorkCapacityBoard slug={slug}/>
 </section></main>;
}
