import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {createFindingVerificationTasks} from "../../../../../../lib/verification-plan";
import {PrintReportButton} from "../../../../../../components/print-report-button";

type Props={params:Promise<{slug:string;findingId:string}>};
export default async function FindingVerificationChecklist({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const tasks=createFindingVerificationTasks(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Verification checklist</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">
   {membership.organization.name} · {finding.severity} · {finding.status}.
   A printable checklist for validating remediation, not an attestation of compliance.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/verification-plan"}>Back to plan</Link></p>
   <p className="action-link"><Link href={base+"/evidence/"+finding.id}>Review evidence</Link></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Finding context</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>First seen</dt><dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Last observed</dt><dd>{finding.lastSeenAt.toISOString()}</dd>
    <dt>Resolution recorded</dt><dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Related actions</dt><dd>{finding.actions.length}</dd>
    <dt>Matched evidence records</dt><dd>{finding.evidence.length}</dd>
   </dl>
   <p className="score-caption">
    Matching evidence by control identifier does not automatically establish that the
    observation covers the finding's entire scope.
   </p>
  </section>
  {tasks.map((task,index)=>(
   <section className="remediation-section" key={task.id}>
    <h2>Checklist {index+1}: {task.title}</h2>
    <p className="priority-score">{task.severity} · {task.status}</p>
    <p>{task.description}</p>
    <h3>What to do next</h3>
    <p>{task.suggestedNextStep}</p>
    <h3>Prerequisites</h3>
    {task.prerequisites.length?
     <ul>{task.prerequisites.map((item,n)=><li key={n}>{item}</li>)}</ul>:
     <p>No additional prerequisites were derived from the stored workflow.</p>}
    <h3>Verification criteria</h3>
    <p>Check these outside this page using authorized observations.</p>
    <ol className="remediation-list">
     {task.successCriteria.map((item,n)=>(
      <li className="remediation-card" key={n}>
       <p><strong>Criterion {n+1}</strong></p>
       <p>{item}</p>
       <p className="score-caption">Result: ____________________</p>
       <p className="score-caption">Evidence reference: ____________________</p>
       <p className="score-caption">Checked by / date: ____________________</p>
      </li>
     ))}
    </ol>
    <h3>Limitations and exceptions</h3>
    {task.warnings.length?<ul>
     {task.warnings.map((warning,n)=><li key={n}>{warning}</li>)}
    </ul>:<p>No additional warnings were derived from the stored action.</p>}
    <h3>Recorded evidence references</h3>
    {task.relatedEvidenceIds.length?(
     <p>{task.relatedEvidenceIds.length} matching evidence record identifiers are held by CyberPilot.
      Review the evidence detail page for provenance and dates.</p>
    ):<p>No exact control-identifier evidence records were matched.</p>}
    <p className="score-caption">
     Last finding observation: {task.lastFindingSeenAt.toISOString()}.
     Last matching observed signal: {task.lastObservationAt?.toISOString()??"Unavailable"}.
     Recorded action verification: {task.verifiedAt?.toISOString()??"Not verified"}.
    </p>
    {task.actionId?<p className="action-link no-print">
     <Link href={base+"/"+task.actionId}>Open action controls</Link>
    </p>:null}
   </section>
  ))}
  <section className="remediation-section">
   <h2>Before recording a successful outcome</h2>
   <p>
    Confirm that each relevant step has been performed. Collect evidence from an
    authorized provider or competent reviewer. Compare it to the original finding,
    using the same scope and control. Only the existing verification workflow may
    change the recorded security state.
   </p>
   <p>
    This checklist is a work aid and does not independently verify a finding.
    Printed results and handwritten entries are not synchronized to the database.
   </p>
  </section>
 </section></main>;
}
