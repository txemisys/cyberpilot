import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {assessClosureReadiness} from "../../../../../../lib/closure-readiness";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function ClosureReadinessDetailPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const review=assessClosureReadiness(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Closure review checklist</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">{membership.organization.name} · {finding.severity} ·
   Inspect the eight evidence and workflow checks before communicating closure.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/closure-readiness"}>Readiness overview</Link></p>
   <p className="action-link"><Link href={base+"/dossiers/"+finding.id}>Evidence dossier</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Evidence chronology</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>Verification checklist</Link></p>
   <PrintReportButton/>
  </div>
  <div className="panel">
   <div><p className="panel-label">Met requirements</p><strong>{review.met}</strong></div>
   <div><p className="panel-label">Missing requirements</p><strong>{review.notMet}</strong></div>
   <div><p className="panel-label">Need human review</p><strong>{review.needsReview}</strong></div>
   <div><p className="panel-label">Not applicable</p><strong>{review.notApplicable}</strong></div>
  </div>
  <section className="remediation-section">
   <h2>Recorded finding context</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>Finding status</dt><dd>{finding.status}</dd>
    <dt>First recorded</dt><dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Most recent finding observation</dt><dd>{finding.lastSeenAt.toISOString()}</dd>
    <dt>Finding resolved timestamp</dt>
    <dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Latest matched observed signal</dt>
    <dd>{review.lastObservationAt?.toISOString()??"Not recorded"}</dd>
    <dt>Latest recorded remediation work</dt>
    <dd>{review.lastWorkAt?.toISOString()??"Not recorded"}</dd>
   </dl>
  </section>
  <section className="remediation-section">
   <h2>Eight closure review gates</h2>
   <ol className="remediation-list">{review.gates.map((gate,index)=>(
    <li className="remediation-card" key={gate.id}>
     <div className="remediation-heading">
      <h3>{index+1}. {gate.label}</h3>
      <span className="role-badge">{gate.result}</span>
     </div>
     <p><strong>Recorded facts:</strong> {gate.explanation}</p>
     <p><strong>Human reviewer action:</strong> {gate.reviewerInstruction}</p>
     {gate.evidenceReferences.length?(
      <details><summary>Linked record identifiers ({gate.evidenceReferences.length})</summary>
       <ul>{gate.evidenceReferences.map(id=><li key={id}>{id}</li>)}</ul>
      </details>
     ):<p className="score-caption">No directly linked record identifiers.</p>}
     <p className="score-caption">Reviewer decision: ____________________</p>
     <p className="score-caption">Evidence reference: ____________________</p>
     <p className="score-caption">Reviewer / date: ____________________</p>
    </li>
   ))}</ol>
  </section>
  <section className="remediation-section">
   <h2>Unmet prerequisites</h2>
   {review.blockedBy.length?(
    <ul>{review.blockedBy.map((label,index)=><li key={index}>{label}</li>)}</ul>
   ):<p>No requirements were automatically classified as missing.
    Remaining human-review gates still require an explicit decision.</p>}
  </section>
  <section className="remediation-section">
   <h2>Evidence limitations</h2>
   {review.warnings.length?(
    <ul>{review.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
   ):<p>No additional limitations were inferred from the available records.</p>}
   <p>
    The checklist is an offline review aid. It never records reviewer attestations
    or changes findings. Only the existing authorized verification workflow can
    record a verified remediation state.
   </p>
  </section>
  <p className="score-caption">
   A human reviewer must inspect evidence conclusions and affected scope.
   A current observation or completed step is not sufficient by itself
   to certify an effective security control.
  </p>
 </section></main>;
}
