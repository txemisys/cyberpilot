import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {buildFindingDossier} from "../../../../../../lib/finding-dossier";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function FindingDossierPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const dossier=buildFindingDossier(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Security evidence dossier</p>
  <h1 className="dashboard-title">{dossier.title}</h1>
  <p className="lede">
   {membership.organization.name} · {dossier.severity} · {dossier.findingStatus}.
   A read-only consolidated record for discussing remediation with a competent reviewer.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/dossiers"}>Back to evidence dossiers</Link></p>
   <p className="action-link"><Link href={base+"/evidence/"+finding.id}>Evidence detail</Link></p>
   <p className="action-link"><Link href={base+"/assurance/"+finding.id}>Control assurance</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Evidence chronology</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>Verification checklist</Link></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/dossiers/${finding.id}`}>
    Download this dossier
   </a></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Executive summary</h2>
   <p>{finding.description}</p>
   <div className="panel">
    <div><p className="panel-label">Finding state</p><strong>{dossier.findingStatus}</strong></div>
    <div><p className="panel-label">Evidence assessment</p><strong>{dossier.assessment}</strong></div>
    <div><p className="panel-label">Assurance level</p><strong>{dossier.assurance}</strong></div>
    <div><p className="panel-label">Evidence gap</p><strong>{dossier.gap}</strong></div>
    <div><p className="panel-label">Recorded observations</p><strong>{dossier.observed}</strong></div>
    <div><p className="panel-label">Verified actions</p><strong>{dossier.verifiedRemediations}</strong></div>
   </div>
   <h3>Recommended next step</h3>
   <p>{dossier.nextAction}</p>
   <p className="score-caption">
    This is a review recommendation derived from stored records, not a new security
    finding or proof of successful control operation.
   </p>
  </section>
  <section className="remediation-section">
   <h2>Recorded dates</h2>
   <dl>
    <dt>First observed finding</dt>
    <dd>{dossier.firstSeenAt.toISOString()}</dd>
    <dt>Most recent finding observation</dt>
    <dd>{dossier.lastSeenAt.toISOString()}</dd>
    <dt>Finding resolved</dt>
    <dd>{dossier.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Last matched observed signal</dt>
    <dd>{dossier.latestEvidenceAt?.toISOString()??"Not recorded"}</dd>
    <dt>Last remediation work</dt>
    <dd>{dossier.latestWorkAt?.toISOString()??"Not recorded"}</dd>
    <dt>Last workflow verification</dt>
    <dd>{dossier.latestVerificationAt?.toISOString()??"Not recorded"}</dd>
   </dl>
   {dossier.latestWorkAt&&
    (!dossier.latestEvidenceAt||
     dossier.latestEvidenceAt.getTime()<dossier.latestWorkAt.getTime())?(
    <p className="permission-warning">
     The most recent matched observed evidence predates recorded remediation
     work. A fresh observation is needed before evaluating the result.
    </p>
   ):null}
  </section>
  {dossier.sections.map((section,index)=>(
   <section className="remediation-section" key={index}>
    <h2>{section.heading}</h2>
    {section.statements.length?(
     <ul>{section.statements.map((statement,i)=><li key={i}>{statement}</li>)}</ul>
    ):<p>No statements are available.</p>}
    {section.warnings.length?(
     <>
      <h3>Section limitations</h3>
      <ul>{section.warnings.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
     </>
    ):null}
   </section>
  ))}
  <section className="remediation-section">
   <h2>Associated remediations</h2>
   {finding.actions.length===0?(
    <p>No remediation workflow is associated with this finding.</p>
   ):(
    <ol className="remediation-list">
     {finding.actions.map(action=>{
      const acknowledged=action.steps.filter((_,i)=>
       action.acknowledgedSteps.has(i)).length;
      const verified=action.status==="VERIFIED"&&action.verifiedAt!==null;
      return <li className="remediation-card" key={action.id}>
       <h3>{action.title}</h3>
       <p>{action.mode} · {action.status}</p>
       <p>Recorded guided work: {acknowledged}/{action.steps.length} steps</p>
       <p>Completed at: {action.completedAt?.toISOString()??"Not recorded"}</p>
       <p>Verified at: {verified?action.verifiedAt?.toISOString():"Not verified"}</p>
       <p className="action-link"><Link href={base+"/"+action.id}>
        Review remediation workflow
       </Link></p>
       <p className="action-link"><Link href={base+"/"+action.id+"/runbook"}>
        Printable work instructions
       </Link></p>
      </li>;
     })}
    </ol>
   )}
  </section>
  <section className="remediation-section">
   <h2>Review limitations</h2>
   {dossier.warnings.length?(
    <ul>{dossier.warnings.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
   ):<p>No further limitations were flagged by the current rules.</p>}
   <p>
    Reviewers must consider the original control scope and the outcome of
    authoritative observations before communicating a security improvement.
    Printed or downloaded reports are snapshots, not synchronized approvals.
   </p>
  </section>
  <p className="score-caption">
   The dossier is tenant-scoped and read-only. It does not execute remediation,
   query LIVE providers, change finding states or recalculate CyberScore.
  </p>
 </section></main>;
}
