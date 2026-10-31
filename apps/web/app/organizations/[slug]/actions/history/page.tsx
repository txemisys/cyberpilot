import { db } from "@cyberpilot/database";
import Link from "next/link";
import { requireOrganizationAccess } from "../../../../lib/organizations";
import {
 buildRemediationActivityTimeline,summarizeRemediationActivity,buildRemediationMilestones,
} from "../../../../lib/remediation-activity";

type Props={params:Promise<{slug:string}>;searchParams:Promise<{action?:string}>};
export default async function RemediationHistoryPage({params,searchParams}:Props){
 const {slug}=await params;
 const {action:requestedAction}=await searchParams;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const [remediations,auditEvents,eventCount]=await Promise.all([
  db.remediation.findMany({
   where:{organizationId},orderBy:[{createdAt:"desc"},{id:"asc"}],take:200,
   select:{
    id:true,title:true,status:true,mode:true,createdAt:true,approvedAt:true,
    startedAt:true,completedAt:true,verifiedAt:true,
    finding:{select:{title:true,status:true,severity:true}},
   },
  }),
  db.auditEvent.findMany({
   where:{organizationId,resourceType:"remediation"},
   orderBy:[{occurredAt:"desc"},{id:"asc"}],take:500,
   select:{id:true,action:true,resourceId:true,occurredAt:true,actorType:true,metadata:true},
  }),
  db.auditEvent.count({where:{organizationId,resourceType:"remediation"}}),
 ]);
 const knownIds=new Set(remediations.map(item=>item.id));
 const selectedId=typeof requestedAction==="string"&&knownIds.has(requestedAction)?requestedAction:null;
 const activity=buildRemediationActivityTimeline(auditEvents,knownIds);
 const displayed=selectedId?activity.filter(x=>x.remediationId===selectedId):activity;
 const digest=summarizeRemediationActivity(displayed);
 const base=`/organizations/${slug}/actions/history`;
 return (
  <main className="shell">
   <section className="dashboard">
    <p className="eyebrow">CyberPilot · Action history</p>
    <h1 className="dashboard-title">What has happened?</h1>
    <p className="lede">Trace recorded remediation activity for {membership.organization.name}. A completed step does not mean the security risk was verified.</p>
    <div className="workspace-links no-print">
     <p className="action-link"><Link href={`/organizations/${slug}/actions`}>Back to action center</Link></p>
     <p className="action-link"><Link href={`/organizations/${slug}`}>Back to workspace</Link></p>
    </div>
    <form action={base} method="get" className="remediation-actions">
     <label htmlFor="history-action">Show activity for</label>
     <select name="action" id="history-action" defaultValue={selectedId??""}>
      <option value="">All recent actions</option>
      {remediations.map(action=><option key={action.id} value={action.id}>{action.title} ({action.id.slice(0,8)})</option>)}
     </select>
     <button className="secondary-button" type="submit">Show history</button>
     <Link href={base}>Clear selection</Link>
    </form>
    <div className="panel">
     <div><p className="panel-label">Recorded events shown</p><p className="panel-value">{digest.total}</p></div>
     <div><p className="panel-label">Approvals</p><p className="panel-value">{digest.approvals}</p></div>
     <div><p className="panel-label">Guided steps acknowledged</p><p className="panel-value">{digest.guidedSteps}</p></div>
     <div><p className="panel-label">Verification events</p><p className="panel-value">{digest.verifications}</p></div>
    </div>
    {eventCount>auditEvents.length?(
      <p className="score-caption">Showing the latest {auditEvents.length} of {eventCount} recorded events. Older events are excluded from these totals.</p>
    ):null}
    {remediations.length===200?(
      <p className="score-caption">History is limited to the 200 most recently created remediation actions.</p>
    ):null}
    {selectedId?(
     <section className="remediation-section" aria-label="Selected action milestones">
      <h2>Action milestones</h2>
      {remediations.filter(x=>x.id===selectedId).map(action=>(
       <article key={action.id} className="remediation-card">
        <h3>{action.title}</h3>
        <p>{action.finding.title} · {action.finding.status}</p>
        <ol>
         {buildRemediationMilestones(action).map(milestone=>(
          <li key={milestone.label}>
           <strong>{milestone.label}</strong>
           <p>{milestone.occurredAt?milestone.occurredAt.toISOString():"Not recorded"}
            {milestone.verified?" · Evidence verified":""}
           </p>
          </li>
         ))}
        </ol>
        <p className="action-link"><Link href={`/organizations/${slug}#remediation-${action.id}`}>Open remediation</Link></p>
       </article>
      ))}
     </section>
    ):null}
    <section className="remediation-section" aria-label="Remediation activity timeline">
     <h2>Activity timeline</h2>
     {displayed.length===0?(
      <p>No recorded activity was found in the available history.</p>
     ):(
      <ol className="remediation-list">
       {displayed.map(item=>(
        <li className="remediation-card" key={item.id}>
         <strong>{item.title}</strong>
         <p>{item.description}</p>
         <p><time dateTime={item.occurredAt.toISOString()}>{item.occurredAt.toISOString()}</time> · {item.actorLabel}</p>
         <p className="action-link"><Link href={`/organizations/${slug}#remediation-${item.remediationId}`}>View related action</Link></p>
        </li>
       ))}
      </ol>
     )}
    </section>
    <p className="score-caption">The timeline reflects stored audit events only; absence of events does not prove work was not performed. No CyberScore values are recalculated.</p>
   </section>
  </main>
 );
}
