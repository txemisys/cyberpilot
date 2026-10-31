import { db } from "@cyberpilot/database";
import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { getGuidedVerificationReadiness } from "../../../../../lib/guided-verification";
import { buildRemediationMilestones, buildRemediationActivityTimeline } from "../../../../../lib/remediation-activity";

type Props={params:Promise<{slug:string;actionId:string}>};
export default async function ActionDetailPage({params}:Props){
  const {slug,actionId}=await params;
  const {membership}=await requireOrganizationAccess(slug);
  const organizationId=membership.organization.id;
  const action=await db.remediation.findFirst({
    where:{organizationId,id:actionId},
    select:{
      id:true,title:true,summary:true,status:true,mode:true,steps:true,verification:true,
      failureCode:true,createdAt:true,updatedAt:true,approvedAt:true,startedAt:true,
      completedAt:true,verifiedAt:true,playbookId:true,
      finding:{select:{id:true,title:true,description:true,status:true,severity:true,lastSeenAt:true}},
    },
  });
  if(!action)notFound();
  const [steps,audits]=await Promise.all([
    db.guidedRemediationStep.findMany({
      where:{organizationId,remediationId:action.id},orderBy:{stepIndex:"asc"},
      select:{stepIndex:true,acknowledgedAt:true},
    }),
    db.auditEvent.findMany({
      where:{organizationId,resourceType:"remediation",resourceId:action.id},
      orderBy:{occurredAt:"desc"},take:100,
      select:{id:true,action:true,resourceId:true,actorType:true,occurredAt:true,metadata:true},
    }),
  ]);
  const instructions=Array.isArray(action.steps)?action.steps.filter((x):x is string=>typeof x==="string"):[];
  const verification=Array.isArray(action.verification)?action.verification.filter((x):x is string=>typeof x==="string"):[];
  const progress=new Set(steps.map(s=>s.stepIndex));
  const readiness=getGuidedVerificationReadiness(instructions.length,progress);
  const history=buildRemediationActivityTimeline(audits,new Set([action.id]));
  const completed=instructions.filter((_,index)=>progress.has(index)).length;
  const canManage=membership.role==="OWNER"||membership.role==="ADMIN";
  const base=`/organizations/${slug}`;
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Remediation details</p>
    <h1 className="dashboard-title">{action.title}</h1>
    <p className="lede">{membership.organization.name} · {action.finding.severity} · {action.mode}</p>
    <p className="action-link"><Link href={base+"/actions"}>Back to action center</Link></p>
    <div className="panel">
      <div><p className="panel-label">Workflow status</p><strong>{action.status}</strong></div>
      <div><p className="panel-label">Guided steps completed</p><strong>{completed}/{instructions.length}</strong></div>
      <div><p className="panel-label">Finding status</p><strong>{action.finding.status}</strong></div>
      <div><p className="panel-label">Last observed</p><strong>{action.finding.lastSeenAt.toISOString()}</strong></div>
    </div>
    <section className="remediation-section">
      <h2>Why this action matters</h2>
      <p>{action.summary}</p>
      <h3>Evidence-backed finding</h3>
      <p><strong>{action.finding.title}</strong> — {action.finding.description}</p>
      <p className="score-caption">The finding is not resolved until fresh evidence confirms the change.</p>
      {action.failureCode?<p className="auth-error">Last execution failed: {action.failureCode}</p>:null}
    </section>
    <section className="remediation-section">
      <h2>Work through the remediation</h2>
      {instructions.length===0?<p>No guided steps are recorded for this remediation.</p>:(
        <ol className="remediation-list">
          {instructions.map((text,index)=>{
            const acknowledged=steps.find(s=>s.stepIndex===index);
            return <li className="remediation-card" key={index}>
              <strong>Step {index+1} {acknowledged?"— acknowledged":""}</strong>
              <p>{text}</p>
              {acknowledged?<p>Recorded: {acknowledged.acknowledgedAt.toISOString()}</p>:null}
              {canManage&&action.mode==="GUIDED"&&action.status==="APPROVED"&&action.finding.status==="OPEN"&&!acknowledged?(
                <form method="post" action={`/api/organizations/${slug}/remediations/${action.id}/progress`}>
                  <input type="hidden" name="stepIndex" value={index}/>
                  <button className="secondary-button" type="submit">Acknowledge step</button>
                </form>
              ):null}
            </li>;
          })}
        </ol>
      )}
      {action.mode==="GUIDED"&&readiness==="READY"&&action.status!=="VERIFIED"?(
        <p className="permission-warning">Every guided step was acknowledged. This is not a verified security fix; request fresh evidence from the workspace before closure.</p>
      ):null}
      {canManage&&action.status==="PROPOSED"&&action.finding.status==="OPEN"?(
        <form method="post" action={`/api/organizations/${slug}/remediations/${action.id}/approve`}>
          <button className="primary-button" type="submit">Approve the remediation plan</button>
        </form>
      ):null}
      {action.status==="APPROVED"&&action.mode==="AUTOMATED"?(
        <p>Automated execution is managed separately through the existing authorized workspace. This page cannot trigger a LIVE change.</p>
      ):null}
    </section>
    <section className="remediation-section">
      <h2>How to verify the result</h2>
      {verification.length?<ol>{verification.map((step,index)=><li key={index}>{step}</li>)}</ol>:<p>No verification checklist has been recorded.</p>}
      <p className="action-link"><Link href={base+`#remediation-${action.id}`}>Open verification controls in workspace</Link></p>
    </section>
    <section className="remediation-section">
      <h2>Recorded milestones</h2>
      <ol>{buildRemediationMilestones(action).map(milestone=>(
        <li key={milestone.label}><strong>{milestone.label}</strong> — {milestone.occurredAt?.toISOString()??"Not recorded"}{milestone.verified?" (verified)":""}</li>
      ))}</ol>
      <h2>Recent activity</h2>
      {history.length?<ol>{history.map(event=>(
        <li key={event.id}><strong>{event.title}</strong> — {event.occurredAt.toISOString()}<p>{event.description}</p></li>
      ))}</ol>:<p>No relevant activity was recorded in the latest 100 events.</p>}
    </section>
    <p className="score-caption">This action page displays stored organization-scoped information and never changes CyberScore.</p>
  </section></main>;
}
