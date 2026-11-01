import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOrganizationAccess } from "../../../../../../lib/organizations";
import { canReadWork } from "../../../../../../lib/remediation-work-input";
import { readStoredIntegrityCapture } from "../../../../../../lib/work-integrity-persistent-captures";

type Props = { params: Promise<{ slug: string; captureId: string }> };
export default async function IntegrityCaptureDetail({ params }: Props) {
  const { slug, captureId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  if (!canReadWork(membership.role)) notFound();
  if (!/^[a-zA-Z0-9_-]{5,100}$/.test(captureId)) notFound();
  const capture = await readStoredIntegrityCapture(membership.organization.id, captureId);
  if (!capture) notFound();
  const base = `/organizations/${encodeURIComponent(slug)}/actions/integrity`;
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Stored integrity evidence</p>
    <h1 className="dashboard-title">Diagnostic capture</h1>
    <p><Link href={base}>Back to history</Link></p>
    <dl>
      <div><dt>Source</dt><dd>{capture.source}</dd></div>
      <div><dt>Captured</dt><dd>{capture.capturedAt}</dd></div>
      <div><dt>Coverage</dt><dd>{capture.complete ? "Declared complete" : "Incomplete"}</dd></div>
      <div><dt>Recorded cases</dt><dd>{capture.cases.length}</dd></div>
    </dl>
    {!capture.complete && <p role="status">Incomplete capture: missing cases cannot be interpreted as resolved.</p>}
    <h2>Recorded diagnostic cases</h2>
    {capture.cases.length === 0 ? <p>No cases were recorded in this capture. This does not prove the environment is secure.</p> :
      <table><thead><tr><th>Severity</th><th>State</th><th>Diagnostic</th><th>Work item</th><th>Coverage</th></tr></thead>
        <tbody>{capture.cases.map(item => <tr key={item.key}>
          <td>{item.severity ?? "Unclassified"}</td><td>{item.state}</td>
          <td><strong>{item.code}</strong><p>{item.diagnostic ?? "No diagnostic text recorded."}</p>
            {item.recommendation && <p>Recommendation: {item.recommendation}</p>}</td>
          <td><code>{item.workItemId}</code><p><Link href={`/organizations/${encodeURIComponent(slug)}/actions/work/integrity`}>Open current work integrity</Link></p></td>
          <td>{item.completeCoverage ? "Declared complete" : "Partial"}</td>
        </tr>)}</tbody></table>}
    <p>Historical diagnostics and review states may be stale. Consult current work records before taking action.</p>
    <p><Link href={`/organizations/${encodeURIComponent(slug)}/actions/work`}>Open remediation coordination</Link></p>
  </section></main>;
}
