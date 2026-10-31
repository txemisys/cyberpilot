import Link from "next/link";
import {requireOrganizationAccess} from "../../../../../lib/organizations";
import {loadReviewData,parseReviewListOptions} from "../../../../../lib/finding-review-data";
import {buildEvidenceSourceCoverage,exportEvidenceSourceCoverage} from "../../../../../lib/evidence-source-coverage";
type Props={params:Promise<{slug:string}>;searchParams:Promise<Record<string,string|undefined>>};
export default async function EvidenceSourceCoveragePage({params,searchParams}:Props){
 const {slug}=await params;
 const {membership}=await requireOrganizationAccess(slug);
 const input=new URLSearchParams();
 for(const [key,value] of Object.entries(await searchParams)){
  if(typeof value==="string")input.set(key,value);
 }
 const settings=parseReviewListOptions(input);
 const data=await loadReviewData(membership.organization.id,{...settings,limit:50,offset:0});
 const report=buildEvidenceSourceCoverage(data.findings);
 const base=`/organizations/${slug}/actions`;
 const coverageText=exportEvidenceSourceCoverage(report);
 return <main className="shell"><section className="dashboard">
  <p className="eyebrow">CyberPilot · Evidence coverage</p>
  <h1 className="dashboard-title">Evidence source coverage</h1>
  <p className="lede">How many findings have exact control-matched records, and what
   kinds of provenance have been recorded? These are data coverage metrics,
   not an assessment of security control effectiveness.</p>
  <div className="workspace-links no-print">
   <p className="action-link"><Link href={base}>Action center</Link></p>
   <p className="action-link"><Link href={base+"/assurance"}>Assurance overview</Link></p>
   <p className="action-link"><Link href={base+"/gaps"}>Evidence gaps</Link></p>
  </div>
  <div className="panel">
   <div><p className="panel-label">Findings reviewed</p><strong>{report.findings}</strong></div>
   <div><p className="panel-label">Matched findings</p><strong>{report.matchedFindings}</strong></div>
   <div><p className="panel-label">Unmatched findings</p><strong>{report.unmatchedFindings}</strong></div>
  </div>
  {data.total>data.findings.length?(
   <p className="permission-warning">
    Coverage metrics represent only the first {data.findings.length} of {data.total}
    matching findings. They are not organization-wide totals.
   </p>
  ):<p className="score-caption">All {data.total} matching findings are included.</p>}
  <section className="remediation-section">
   <h2>Evidence provenance by source type</h2>
   <table><thead><tr><th scope="col">Source</th><th scope="col">Records</th>
    <th scope="col">Findings</th><th scope="col">Dated observations</th></tr></thead>
    <tbody>{report.sourceSummaries.map(source=>(
     <tr key={source.source}><th scope="row">{source.source}</th>
      <td>{source.records}</td><td>{source.findings}</td>
      <td>{source.withDatedObservations}</td></tr>
    ))}</tbody>
   </table>
   <p className="score-caption">A matching record may be outdated or unrelated in scope.
    OBSERVED denotes provenance, not automatically a passing control test.</p>
  </section>
  <section className="remediation-section">
   <h2>Evidence coverage by finding severity</h2>
   {report.bySeverity.length?(
    <table><thead><tr><th>Severity</th><th>Findings</th>
     <th>Matched</th><th>Unmatched</th></tr></thead><tbody>
     {report.bySeverity.map(severity=>(
      <tr key={severity.severity}><th>{severity.severity}</th>
       <td>{severity.findings}</td><td>{severity.matched}</td>
       <td>{severity.unmatched}</td></tr>
     ))}</tbody></table>
   ):<p>No findings are available for this review.</p>}
  </section>
  <section className="remediation-section">
   <h2>Recent source activity (UTC)</h2>
   {report.recordingMonths.length?(
    <table><thead><tr><th>Month</th><th>Records</th>
     <th>Observed</th><th>Declared</th><th>Inconclusive</th></tr></thead><tbody>
     {report.recordingMonths.map(month=>(
      <tr key={month.month}><th>{month.month}</th><td>{month.records}</td>
       <td>{month.observed}</td><td>{month.declared}</td>
       <td>{month.inconclusive}</td></tr>
     ))}</tbody></table>
   ):<p>No dated matching evidence records are available.</p>}
  </section>
  <details><summary>Read-only coverage summary</summary><pre>{coverageText}</pre></details>
  <p className="score-caption">All records are restricted to the authorized organization.
   No LIVE collection, remediation execution, or CyberScore recalculation occurs.</p>
 </section></main>;
}
