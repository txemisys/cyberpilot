import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {buildManagementDecisions} from "../../../../../../lib/management-decision-board";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function ManagementFindingDecisionPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const decisions=buildManagementDecisions(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Management decision agenda</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">
   {membership.organization.name} · {finding.severity}. Review the recommended
   actions, outstanding prerequisites and evidence requirements before approving
   work or communicating a security improvement.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/decisions"}>Back to decision board</Link></p>
   <p className="action-link"><Link href={base+"/dossiers/"+finding.id}>Evidence dossier</Link></p>
   <p className="action-link"><Link href={base+"/closure-readiness/"+finding.id}>Closure readiness</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Evidence chronology</Link></p>
   <p className="action-link">
    <a href={`/api/organizations/${slug}/actions/decisions/${finding.id}`}>
     Download this finding's management decision briefing
    </a>
   </p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Recorded scope and status</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>Current finding status</dt><dd>{finding.status}</dd>
    <dt>Finding first seen</dt><dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Latest finding observation</dt><dd>{finding.lastSeenAt.toISOString()}</dd>
    <dt>Finding resolution timestamp</dt>
    <dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Linked remediations</dt><dd>{finding.actions.length}</dd>
    <dt>Matching evidence records</dt><dd>{finding.evidence.length}</dd>
   </dl>
  </section>
  <section className="remediation-section">
   <h2>Proposed management decisions</h2>
   {decisions.length===0?<p>No specific decisions could be derived from these records.</p>:(
    <ol className="remediation-list">{decisions.map((item,index)=>(
     <li className="remediation-card" key={item.id}>
      <div className="remediation-heading">
       <div><p className="priority-score">{item.priority} · {item.category}</p>
        <h3>{index+1}. {item.title}</h3></div>
       <span className="role-badge">{item.severity}</span>
      </div>
      <p><strong>Recorded situation:</strong> {item.reason}</p>
      <p><strong>Suggested next action:</strong> {item.recommendedAction}</p>
      <h4>Before authorizing work</h4>
      {item.prerequisites.length?<ul>{item.prerequisites.map((step,i)=>(
       <li key={i}>{step}</li>
      ))}</ul>:<p>No extra prerequisites were derived.</p>}
      <h4>Criteria for an evidence-based outcome</h4>
      <ol>{item.successCriteria.map((criterion,i)=><li key={i}>{criterion}</li>)}</ol>
      <h4>Evidence references</h4>
      <dl>
       <dt>Last finding observation</dt><dd>{item.lastFindingSeenAt.toISOString()}</dd>
       <dt>Latest matched observed signal</dt>
       <dd>{item.lastObservedAt?.toISOString()??"Not recorded"}</dd>
       <dt>Last remediation work</dt>
       <dd>{item.lastRemediationAt?.toISOString()??"Not recorded"}</dd>
       <dt>Recorded verification</dt>
       <dd>{item.verificationAt?.toISOString()??"Not recorded"}</dd>
      </dl>
      {item.warnings.length?(
       <>
        <h4>Review limitations</h4>
        <ul>{item.warnings.map((warning,i)=><li key={i}>{warning}</li>)}</ul>
       </>
      ):null}
      <div className="no-print">
       <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>
        Open detailed verification checklist
       </Link></p>
       {item.actionId?<p className="action-link">
        <Link href={base+"/"+item.actionId}>Open existing approval and remediation controls</Link>
       </p>:null}
      </div>
      <p className="score-caption">Management decision: ____________________</p>
      <p className="score-caption">Decision owner / date: ____________________</p>
      <p className="score-caption">Evidence reference: ____________________</p>
     </li>
    ))}</ol>
   )}
  </section>
  <section className="remediation-section">
   <h2>Before closing the meeting</h2>
   <p>
    Assign the required review to an authorized person using your normal
    governance process. Do not treat an offline handwritten decision as an
    approval in CyberPilot. Use the existing approved workflow for any
    change requiring authorization.
   </p>
   <p>
    Return to the verification checklist once new observations exist.
    Acknowledgement or execution alone does not establish risk reduction.
   </p>
  </section>
  <p className="score-caption">
   This document is a snapshot of stored evidence and does not make
   LIVE calls, approve actions, modify findings, or recalculate CyberScore.
  </p>
 </section></main>;
}
