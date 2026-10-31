import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {reconcileFinding} from "../../../../../../lib/remediation-reconciliation";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function FindingReconciliationPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const entries=reconcileFinding(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Outcome audit</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">{membership.organization.name} · {finding.severity} ·
   Review each linked remediation against the current finding status,
   recorded work and the latest matched observed control signal.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/reconciliation"}>All reconciled outcomes</Link></p>
   <p className="action-link"><Link href={base+"/dossiers/"+finding.id}>Evidence dossier</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Event chronology</Link></p>
   <p className="action-link"><Link href={base+"/closure-readiness/"+finding.id}>Closure requirements</Link></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Finding state</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>Current finding status</dt><dd>{finding.status}</dd>
    <dt>First recorded</dt><dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Last finding observation</dt><dd>{finding.lastSeenAt.toISOString()}</dd>
    <dt>Recorded resolution date</dt>
    <dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Linked remediation workflows</dt><dd>{finding.actions.length}</dd>
   </dl>
  </section>
  <section className="remediation-section">
   <h2>Remediation reconciliation</h2>
   <ol className="remediation-list">{entries.map(item=>(
    <li className="remediation-card" key={item.id}>
     <div className="remediation-heading">
      <div><p className="priority-score">{item.severity} · {item.outcome}</p>
       <h3>{item.actionTitle??"Finding without a linked remediation"}</h3></div>
      <span className="role-badge">{item.needsReviewer?"Review":"Recorded states aligned"}</span>
     </div>
     <p><strong>Current action status:</strong> {item.actionStatus??"Not recorded"}</p>
     <p><strong>Interpretation:</strong> {item.explanation}</p>
     <p><strong>Next action:</strong> {item.nextAction}</p>
     <dl>
      <dt>Latest matching observed signal</dt>
      <dd>{item.lastObservationAt?.toISOString()??"Not recorded"}</dd>
      <dt>Last work activity</dt>
      <dd>{item.lastWorkAt?.toISOString()??"Not recorded"}</dd>
      <dt>Workflow verification</dt>
      <dd>{item.verifiedAt?.toISOString()??"Not recorded"}</dd>
      <dt>Finding closure</dt>
      <dd>{item.resolvedAt?.toISOString()??"Not recorded"}</dd>
     </dl>
     {item.warnings.length?(
      <>
       <h4>Limitations requiring attention</h4>
       <ul>{item.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
      </>
     ):null}
     <p className="score-caption">Review result: ____________________</p>
     <p className="score-caption">Responsible reviewer / date: ____________________</p>
     <p className="score-caption">Evidence reference: ____________________</p>
     {item.actionId?(
      <p className="action-link no-print"><Link href={base+"/"+item.actionId}>
       Open existing remediation controls
      </Link></p>
     ):null}
    </li>
   ))}</ol>
  </section>
  <section className="remediation-section">
   <h2>Review before communicating a result</h2>
   <p>Verify that the action and source evidence cover the same control
    and affected asset scope. A recorded resolution or verification timestamp
    does not independently establish an effective security control.</p>
   <p>Use the existing authorized workflow to record real approvals or
    verification. This report does not synchronize offline reviewer notes.</p>
  </section>
  <p className="score-caption">Tenant-scoped, read-only reconciliation.
   No provider collection, workflow updates or CyberScore changes occur.</p>
 </section></main>;
}
