import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {buildAuditPacket} from "../../../../../../lib/audit-preparation";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function AuditPacketPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const packet=buildAuditPacket(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Audit preparation packet</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">
   {membership.organization.name} · A read-only documentation checklist
   for review by an authorized auditor or security professional.
  </p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/audit"}>Audit readiness overview</Link></p>
   <p className="action-link"><Link href={base+"/dossiers/"+finding.id}>Evidence dossier</Link></p>
   <p className="action-link"><Link href={base+"/chronology/"+finding.id}>Chronology</Link></p>
   <p className="action-link"><Link href={base+"/closure-readiness/"+finding.id}>Closure review</Link></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/audit/${finding.id}`}>
    Download this audit preparation packet
   </a></p>
   <PrintReportButton/>
  </div>
  <div className="panel">
   <div><p className="panel-label">Questions</p><strong>{packet.questions.length}</strong></div>
   <div><p className="panel-label">Supported facts</p><strong>{packet.supported}</strong></div>
   <div><p className="panel-label">Incomplete records</p><strong>{packet.incomplete}</strong></div>
   <div><p className="panel-label">Require review</p><strong>{packet.reviewRequired}</strong></div>
  </div>
  <section className="remediation-section">
   <h2>Recorded finding context</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>Severity</dt><dd>{finding.severity}</dd>
    <dt>Status</dt><dd>{finding.status}</dd>
    <dt>First seen</dt><dd>{finding.firstSeenAt.toISOString()}</dd>
    <dt>Last seen</dt><dd>{finding.lastSeenAt.toISOString()}</dd>
    <dt>Resolved timestamp</dt>
    <dd>{finding.resolvedAt?.toISOString()??"Not recorded"}</dd>
    <dt>Matched evidence records</dt><dd>{finding.evidence.length}</dd>
    <dt>Linked remediation workflows</dt><dd>{finding.actions.length}</dd>
   </dl>
  </section>
  <section className="remediation-section">
   <h2>Documentation checks</h2>
   <ol className="remediation-list">
    {packet.questions.map((question,index)=>(
     <li className="remediation-card" key={question.id}>
      <p className="priority-score">{question.category} · {question.status}</p>
      <h3>{index+1}. {question.question}</h3>
      <p><strong>Recorded facts:</strong> {question.explanation}</p>
      <p><strong>Review instruction:</strong> {question.reviewInstruction}</p>
      {question.references.length?(
       <details>
        <summary>Related record identifiers ({question.references.length})</summary>
        <ul>{question.references.map(reference=><li key={reference}>{reference}</li>)}</ul>
       </details>
      ):<p className="score-caption">No linked record identifiers are available.</p>}
      <p className="score-caption">Auditor determination: ____________________</p>
      <p className="score-caption">Supporting reference: ____________________</p>
      <p className="score-caption">Auditor name and date: ____________________</p>
     </li>
    ))}
   </ol>
  </section>
  <section className="remediation-section">
   <h2>Limits of the evidence packet</h2>
   {packet.limitations.length?(
    <ul>{packet.limitations.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
   ):<p>Independent verification remains necessary.</p>}
   <p>
    Missing records are gaps in this documentation view, not proof
    that the underlying control is absent. A recorded status is not an
    independent audit conclusion. Offline review marks are not persisted.
   </p>
  </section>
  <p className="score-caption">
   This report does not grant approvals, collect new provider evidence,
   change findings, verify remediations or recalculate CyberScore.
  </p>
 </section></main>;
}
