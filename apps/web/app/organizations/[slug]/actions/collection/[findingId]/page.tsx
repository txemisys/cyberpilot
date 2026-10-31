import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {deriveEvidenceCollectionInstruction} from "../../../../../../lib/evidence-collection-planner";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={params:Promise<{slug:string;findingId:string}>};
export default async function CollectionChecklistPage({params}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const plan=deriveEvidenceCollectionInstruction(finding);
 const base=`/organizations/${slug}/actions`;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence collection checklist</p>
  <h1 className="dashboard-title">{finding.title}</h1>
  <p className="lede">{membership.organization.name} · {finding.severity} ·
   Preparation and review checklist for authorized evidence collection.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/collection"}>Collection overview</Link></p>
   <p className="action-link"><Link href={base+"/evidence/"+finding.id}>Evidence provenance</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>Verification plan</Link></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Control scope</h2>
   <p>{finding.description}</p>
   <dl>
    <dt>Finding status</dt><dd>{finding.status}</dd>
    <dt>Evidence readiness</dt><dd>{plan.state}</dd>
    <dt>Last matched observation</dt>
    <dd>{plan.observationAt?.toISOString()??"Not recorded"}</dd>
    <dt>Last remediation work</dt>
    <dd>{plan.latestWorkAt?.toISOString()??"Not recorded"}</dd>
    <dt>Recorded observed signals</dt><dd>{plan.observedRecordIds.length}</dd>
    <dt>Declarations</dt><dd>{plan.declaredRecordIds.length}</dd>
    <dt>Inconclusive records</dt><dd>{plan.inconclusiveRecordIds.length}</dd>
   </dl>
   <h3>{plan.headline}</h3>
   <p>{plan.purpose}</p>
  </section>
  <section className="remediation-section">
   <h2>Before collecting data</h2>
   <p>Review each requirement with an authorized security reviewer.
    Handwritten or printed check marks are not synchronized into CyberPilot.</p>
   <ol className="remediation-list">{plan.instructions.map((instruction,index)=>(
    <li className="remediation-card" key={index}>
     <h3>Preparation step {index+1}</h3>
     <p>{instruction}</p>
     <p className="score-caption">Reviewed by: ____________________</p>
     <p className="score-caption">Date / evidence reference: ____________________</p>
    </li>
   ))}</ol>
  </section>
  <section className="remediation-section">
   <h2>Review the collected observation</h2>
   <p>Do not consider a successful collection operation equivalent to an
    effective security configuration. The result and scope must be inspected.</p>
   <ol className="remediation-list">{plan.reviewCriteria.map((criterion,index)=>(
    <li className="remediation-card" key={index}>
     <h3>Criterion {index+1}</h3>
     <p>{criterion}</p>
     <p className="score-caption">Outcome: ____________________</p>
     <p className="score-caption">Observation reference: ____________________</p>
     <p className="score-caption">Reviewer / time: ____________________</p>
    </li>
   ))}</ol>
  </section>
  <section className="remediation-section">
   <h2>Known limitations</h2>
   {plan.cautions.length?(
    <ul>{plan.cautions.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
   ):<p>No additional limitations were derived from stored findings and workflows.</p>}
   <p>Exact control identifier matching can miss relevant records with a
    different identifier or asset scope. Document any mapping discrepancy
    before making a closure decision.</p>
  </section>
  <section className="remediation-section">
   <h2>Associated operational records</h2>
   {plan.linkedActionIds.length?(
    <ul>{plan.linkedActionIds.map(id=>(
     <li key={id}><Link href={base+"/"+id}>Review related remediation</Link></li>
    ))}</ul>
   ):<p>No remediation is linked to this finding.</p>}
   <p className="action-link"><Link href={base+"/closure-readiness/"+finding.id}>
    Review closure-readiness requirements
   </Link></p>
  </section>
  <p className="score-caption">
   This checklist is read-only; it does not fetch data from LIVE providers,
   execute changes, create attestations or alter CyberScore.
  </p>
 </section></main>;
}
