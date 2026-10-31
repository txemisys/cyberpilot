import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {assessControlAssurance} from "../../../../../../lib/control-assurance";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function AssuranceDetailPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const review=assessControlAssurance(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Assurance drilldown</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">{membership.organization.name} · {finding.severity} ·
   Review the evidence supporting this control before asserting it is effective.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/assurance"}>Control assurance overview</Link></p>
   <p className="action-link"><Link href={base+"/evidence/"+finding.id}>Evidence provenance</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>Verification checklist</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Compare evidence and remediation chronology</Link></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Current assessment</h2>
   <div className="panel">
    <div><p className="panel-label">Finding status</p><strong>{review.findingStatus}</strong></div>
    <div><p className="panel-label">Evidence classification</p><strong>{review.level}</strong></div>
    <div><p className="panel-label">Recorded observations</p><strong>{review.observations}</strong></div>
    <div><p className="panel-label">Declarations</p><strong>{review.declarations}</strong></div>
    <div><p className="panel-label">Unknown or error records</p><strong>{review.unknown+review.errors}</strong></div>
    <div><p className="panel-label">Verified workflows</p><strong>{review.verifiedWorkflows}</strong></div>
   </div>
   <h3>{review.decisionReason}</h3>
   <p>{review.recommendedAction}</p>
   <p className="score-caption">
    Evidence classification is operational context, not a certificate of effective control.
   </p>
  </section>
  <section className="remediation-section">
   <h2>Timeline comparison</h2>
   <dl>
    <dt>Finding first seen</dt>
    <dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Finding last seen</dt>
    <dd>{review.lastFindingAt.toISOString()}</dd>
    <dt>Finding resolved timestamp</dt>
    <dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Most recent matched observed evidence</dt>
    <dd>{review.lastObservationAt?.toISOString()??"Not recorded"}</dd>
    <dt>Most recent remediation work</dt>
    <dd>{review.lastWorkAt?.toISOString()??"Not recorded"}</dd>
    <dt>Most recent workflow verification</dt>
    <dd>{review.lastVerificationAt?.toISOString()??"Not recorded"}</dd>
   </dl>
   {review.observedAfterWork?(
    <p className="permission-warning">
     An observation was recorded after remediation activity. Its conclusion must
     still be reviewed before claiming that the security finding is fixed.
    </p>
   ):(review.lastWorkAt?(
    <p className="permission-warning">
     No matched observation is known to follow the recorded work.
     Obtain fresh evidence before assessing the outcome.
    </p>
   ):<p>No remediation work timestamp is recorded for comparison.</p>)}
  </section>
  <section className="remediation-section">
   <h2>Source evidence records</h2>
   {finding.evidence.length===0?(
    <div className="empty-state">
     <p>No exact control-identifier evidence records were matched.</p>
     <p>Check the control mapping before concluding that the source has no data.</p>
    </div>
   ):(
    <ol className="remediation-list">{finding.evidence.map(evidence=>(
     <li className="remediation-card" key={evidence.id}>
      <div className="remediation-heading">
       <h3>{evidence.category}</h3><span className="role-badge">{evidence.source}</span>
      </div>
      <p>{evidence.summary}</p>
      <p>Captured: {evidence.capturedAt?.toISOString()??"Not recorded"}</p>
      <p>Observed: {evidence.lastObservedAt?.toISOString()??"Not recorded"}</p>
      {evidence.source==="DECLARED"?
       <p className="score-caption">A declaration is not independent observation.</p>:null}
      {evidence.source==="ERROR"||evidence.source==="UNKNOWN"?
       <p className="permission-warning">The record is inconclusive and requires investigation.</p>:null}
     </li>
    ))}</ol>
   )}
  </section>
  <section className="remediation-section">
   <h2>Related remediation workflows</h2>
   {finding.actions.length===0?<p>No remediation workflow was recorded.</p>:(
    <ol className="remediation-list">{finding.actions.map(action=>{
     const completed=action.steps.filter((_,index)=>action.acknowledgedSteps.has(index)).length;
     const verified=action.status==="VERIFIED"&&action.verifiedAt!==null;
     return <li className="remediation-card" key={action.id}>
      <h3>{action.title}</h3>
      <p>{action.mode} · {action.status}</p>
      <p>Guided work acknowledged: {completed}/{action.steps.length}</p>
      <p>Work completed: {action.completedAt?.toISOString()??"Not recorded"}</p>
      <p>Verification: {verified?(
       action.verifiedAt?.toISOString()
      ):"Not verified"}</p>
      {action.verification.length?(
       <details><summary>Recorded verification requirements</summary>
        <ol>{action.verification.map((criterion,index)=><li key={index}>{criterion}</li>)}</ol>
       </details>
      ):null}
      <p className="action-link"><Link href={base+"/"+action.id}>Open action details</Link></p>
     </li>;
    })}</ol>
   )}
  </section>
  <section className="remediation-section">
   <h2>Assurance limitations</h2>
   {review.limitations.length?(
    <ul>{review.limitations.map((text,index)=><li key={index}>{text}</li>)}</ul>
   ):<p>No additional limitations were identified by these classification rules.</p>}
   <p>Independent review of scope and evidence remains necessary for communicating security outcomes.</p>
  </section>
  <p className="score-caption">
   This review uses existing tenant-scoped records only. It does not modify findings,
   perform provider scans or alter the CyberScore.
  </p>
 </section></main>;
}
