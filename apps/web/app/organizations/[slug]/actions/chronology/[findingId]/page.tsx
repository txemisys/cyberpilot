import Link from "next/link";
import {notFound} from "next/navigation";
import {requireOrganizationAccess} from "../../../../../../lib/organizations";
import {loadSingleFindingReview} from "../../../../../../lib/finding-review-data";
import {buildControlChronology,filterControlChronology} from "../../../../../../lib/control-chronology";
import {PrintReportButton} from "../../../../../../components/print-report-button";
type Props={
 params:Promise<{slug:string;findingId:string}>;
 searchParams:Promise<{source?:string}>;
};
export default async function ControlChronologyPage({params,searchParams}:Props){
 const {slug,findingId}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const finding=await loadSingleFindingReview(membership.organization.id,findingId);
 if(!finding)notFound();
 const {source}=await searchParams;
 const filter=source==="finding"||source==="workflow"||source==="evidence"?source:"all";
 const chronology=buildControlChronology(finding);
 const events=filterControlChronology(chronology,filter);
 const base=`/organizations/${slug}/actions`;
 const route=base+"/chronology/"+finding.id;
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Control history</p>
  <h1 className="dashboard-title">Evidence chronology</h1>
  <p className="lede">{finding.title} · {finding.severity}. Compare when remediation
   occurred with the timestamps of the available observed control evidence.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base+"/assurance/"+finding.id}>Assurance review</Link></p>
   <p className="action-link"><Link href={base+"/evidence/"+finding.id}>Evidence details</Link></p>
   <p className="action-link"><Link href={base+"/verification-plan/"+finding.id}>Verification checklist</Link></p>
   <p className="action-link"><a href={`/api/organizations/${slug}/actions/chronology/${finding.id}`}>Download chronology</a></p>
   <PrintReportButton/>
  </div>
  <section className="remediation-section">
   <h2>Recorded coverage</h2>
   <div className="panel">
    <div><p className="panel-label">Events</p><strong>{chronology.count}</strong></div>
    <div><p className="panel-label">Finding events</p><strong>{chronology.findingEvents}</strong></div>
    <div><p className="panel-label">Workflow events</p><strong>{chronology.workflowEvents}</strong></div>
    <div><p className="panel-label">Observed signals</p><strong>{chronology.observations}</strong></div>
    <div><p className="panel-label">Inconclusive records</p><strong>{chronology.unknownEvidenceEvents}</strong></div>
   </div>
   <dl>
    <dt>Last recorded remediation work</dt>
    <dd>{chronology.lastWorkAt?.toISOString()??"Not recorded"}</dd>
    <dt>Last matched observed signal</dt>
    <dd>{chronology.lastObservationAt?.toISOString()??"Not recorded"}</dd>
    <dt>Latest verified action</dt>
    <dd>{chronology.lastVerificationAt?.toISOString()??"Not recorded"}</dd>
   </dl>
   {chronology.observationAfterWork?(
    <p className="score-caption">
     At least one observation follows the recorded remediation work. Its control
     scope and result must still be checked before claiming successful remediation.
    </p>
   ):(
    <p className="permission-warning">
     The chronology does not establish an observed control result after remediation.
    </p>
   )}
  </section>
  <section className="remediation-section">
   <h2>Important limitations</h2>
   {chronology.warnings.length?(
    <ul>{chronology.warnings.map((warning,index)=><li key={index}>{warning}</li>)}</ul>
   ):<p>No additional timing conflicts were detected by these rules.</p>}
   <p>Control identifier matching and stored workflow timestamps may be incomplete.
    No date should be interpreted as an independently verified fix without its result.</p>
  </section>
  <nav aria-label="Timeline source filters" className="workspace-links no-print">
   <p className="action-link"><Link href={route} aria-current={filter==="all"?"page":undefined}>All events</Link></p>
   <p className="action-link"><Link href={route+"?source=finding"} aria-current={filter==="finding"?"page":undefined}>Finding</Link></p>
   <p className="action-link"><Link href={route+"?source=workflow"} aria-current={filter==="workflow"?"page":undefined}>Remediation</Link></p>
   <p className="action-link"><Link href={route+"?source=evidence"} aria-current={filter==="evidence"?"page":undefined}>Evidence</Link></p>
  </nav>
  <section className="remediation-section">
   <h2>Recorded events (newest first)</h2>
   {events.length===0?<p>No dated records match this source filter.</p>:(
    <ol className="remediation-list">{events.map(event=>(
     <li className="remediation-card" key={event.id}>
      <p className="priority-score">{event.provenance} · {event.kind}</p>
      <h3>{event.title}</h3>
      <p><time dateTime={event.at.toISOString()}>{event.at.toISOString()}</time></p>
      <p>{event.detail}</p>
      {event.actionId?<p className="action-link">
       <Link href={base+"/"+event.actionId}>Review related remediation</Link>
      </p>:null}
      {event.evidenceId?<p className="action-link">
       <Link href={base+"/evidence/"+finding.id}>Review evidence provenance</Link>
      </p>:null}
     </li>
    ))}</ol>
   )}
  </section>
  <p className="score-caption">
   This chronology is read-only and limited to data already stored for the
   authorized organization. It never runs a provider scan or changes CyberScore.
  </p>
 </section></main>;
}
