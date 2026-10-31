import {db} from "@cyberpilot/database";
import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {prioritizeActionQueue,summarizeActionQueue} from "../../../../../lib/remediation-action-queue";

type Props={params:Promise<{slug:string}>};
export default async function ActionQueuePage({params}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const actions=await db.remediation.findMany({
  where:{organizationId,status:{not:"VERIFIED"}},
  orderBy:[{createdAt:"asc"},{id:"asc"}],take:300,
  select:{
   id:true,title:true,status:true,mode:true,steps:true,createdAt:true,verifiedAt:true,
   finding:{select:{severity:true,status:true}},
  },
 });
 const acknowledgements=await db.guidedRemediationStep.findMany({
  where:{organizationId,remediationId:{in:actions.map(x=>x.id)}},
  select:{remediationId:true,stepIndex:true},
 });
 const byAction=new Map<string,Set<number>>();
 for(const item of acknowledgements){
  const steps=byAction.get(item.remediationId)??new Set<number>();
  steps.add(item.stepIndex);byAction.set(item.remediationId,steps);
 }
 const rows=actions.map(action=>{
  const instructions=Array.isArray(action.steps)?
   action.steps.filter((step):step is string=>typeof step==="string"):[];
  return {
   id:action.id,title:action.title,status:action.status,mode:action.mode,
   severity:action.finding.severity,findingStatus:action.finding.status,
   createdAt:action.createdAt,verifiedAt:action.verifiedAt,
   stepCount:instructions.length,
   acknowledgedCount:instructions.filter((_,index)=>byAction.get(action.id)?.has(index)).length,
  };
 });
 const queue=prioritizeActionQueue(rows);
 const totals=summarizeActionQueue(queue);
 const count=await db.remediation.count({where:{organizationId,status:{not:"VERIFIED"}}});
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Work queue</p>
  <h1 className="dashboard-title">What should we do next?</h1>
  <p className="lede">{membership.organization.name} · Suggested order based on stored action status, verification readiness and severity.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={`/organizations/${slug}/actions`}>All security actions</Link></p>
   <p className="action-link"><Link href={`/organizations/${slug}`}>Back to workspace</Link></p>
  </div>
  <div className="panel">
   <div><p className="panel-label">Actions in queue</p><strong>{totals.total}</strong></div>
   <div><p className="panel-label">Ready for evidence review</p><strong>{totals.verify}</strong></div>
   <div><p className="panel-label">Failed actions</p><strong>{totals.failed}</strong></div>
   <div><p className="panel-label">Proposed plans</p><strong>{totals.unstarted}</strong></div>
  </div>
  {count>actions.length?<p className="permission-warning">This queue includes the oldest {actions.length} of {count} actions. Additional actions are not represented in its priority ordering.</p>:null}
  {queue.length===0?<p>No unverified remediation actions are recorded.</p>:(
   <ol className="remediation-list">{queue.map(item=>(
    <li key={item.id} className="remediation-card">
     <div className="remediation-heading">
      <div><p className="priority-score">{item.severity} · {item.bucket}</p><h2>{item.title}</h2></div>
      <span className="role-badge">{item.status}</span>
     </div>
     <p><strong>Suggested next action:</strong> {item.nextAction}</p>
     {item.progressPercent!==null?<p>Recorded guided progress: {item.acknowledgedCount} / {item.stepCount} ({item.progressPercent}%). This is not evidence of a verified fix.</p>:null}
     <p className="action-link"><Link href={`/organizations/${slug}/actions/${item.id}`}>Open actionable details</Link></p>
    </li>
   ))}</ol>
  )}
  <p className="score-caption">Queue priorities are operational recommendations, not independent findings or changes to CyberScore.</p>
 </section></main>;
}
