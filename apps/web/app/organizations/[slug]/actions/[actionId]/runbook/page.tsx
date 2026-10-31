import { db } from "@cyberpilot/database";
import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { assessRunbookReadiness,normalizeRunbookSteps } from "../../../../../../lib/remediation-runbook";
import { PrintReportButton } from "../../../../../../components/print-report-button";

type Props={params:Promise<{slug:string;actionId:string}>};
export default async function RemediationRunbookPage({params}:Props){
 const {slug,actionId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const organizationId=membership.organization.id;
 const [action,progress]=await Promise.all([
  db.remediation.findFirst({
   where:{organizationId,id:actionId},
   select:{
    id:true,title:true,summary:true,status:true,mode:true,steps:true,verification:true,
    createdAt:true,approvedAt:true,startedAt:true,completedAt:true,verifiedAt:true,
    finding:{select:{title:true,status:true,severity:true}},
   },
  }),
  db.guidedRemediationStep.findMany({
   where:{organizationId,remediationId:actionId},select:{stepIndex:true,acknowledgedAt:true},
   orderBy:{stepIndex:"asc"},
  }),
 ]);
 if(!action)notFound();
 const instructions=normalizeRunbookSteps(action.steps);
 const verification=normalizeRunbookSteps(action.verification);
 const acknowledgedSteps=new Set(progress.map(p=>p.stepIndex));
 const readiness=assessRunbookReadiness({
  id:action.id,title:action.title,summary:action.summary,status:action.status,mode:action.mode,
  severity:action.finding.severity,findingTitle:action.finding.title,findingStatus:action.finding.status,
  instructions,verification,acknowledgedSteps,
  createdAt:action.createdAt,approvedAt:action.approvedAt,startedAt:action.startedAt,
  completedAt:action.completedAt,verifiedAt:action.verifiedAt,
 });
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Action runbook</p>
  <h1 className="dashboard-title">{action.title}</h1>
  <p className="lede">{membership.organization.name} · A practical plan for performing work and checking the result.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={`/organizations/${slug}/actions/${action.id}`}>Back to action details</Link></p>
   <p className="action-link"><Link href={`/organizations/${slug}/actions`}>All actions</Link></p>
   <PrintReportButton/>
  </div>
  <div className="panel">
   <div><p className="panel-label">Finding severity</p><strong>{action.finding.severity}</strong></div>
   <div><p className="panel-label">Action status</p><strong>{action.status}</strong></div>
   <div><p className="panel-label">Guided work</p><strong>{readiness.completed} / {readiness.total}</strong></div>
   <div><p className="panel-label">Evidence verification</p><strong>{readiness.verified?"Recorded":"Not verified"}</strong></div>
  </div>
  <section className="remediation-section">
   <h2>What to address</h2>
   <p>{action.summary}</p>
   <p><strong>Security finding:</strong> {action.finding.title} ({action.finding.status})</p>
  </section>
  <section className="remediation-section">
   <h2>Work instructions</h2>
   {instructions.length?(
    <ol className="remediation-list">{instructions.map((step,index)=>(
     <li className="remediation-card" key={index}>
      <strong>Step {index+1} — {acknowledgedSteps.has(index)?"Acknowledged":"Not acknowledged"}</strong>
      <p>{step}</p>
      {progress.find(item=>item.stepIndex===index)?.acknowledgedAt?(
       <p className="score-caption">Recorded at {progress.find(item=>item.stepIndex===index)?.acknowledgedAt.toISOString()}</p>
      ):null}
     </li>
    ))}</ol>
   ):<p>No guided instructions were recorded for this action.</p>}
  </section>
  <section className="remediation-section">
   <h2>Verification checklist</h2>
   <p>Use these checks after the changes have been performed. Checking a box on paper does not alter the finding.</p>
   {verification.length?<ol>{verification.map((step,index)=><li key={index}>{step}</li>)}</ol>:<p>No verification instructions were recorded.</p>}
  </section>
  <section className="remediation-section">
   <h2>Next operational step</h2>
   <p>{readiness.notice}</p>
   <p className="action-link no-print"><Link href={`/organizations/${slug}#remediation-${action.id}`}>Open workspace verification controls</Link></p>
  </section>
  <p className="score-caption">Printed copies are snapshots of stored data. They do not constitute proof of compliance or successful remediation.</p>
 </section></main>;
}
