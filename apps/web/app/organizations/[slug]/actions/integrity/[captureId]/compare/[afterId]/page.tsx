import Link from "next/link";
import { notFound } from "next/navigation";
import { requireOrganizationAccess } from "../../../../../../../../lib/organizations";
import { canReadWork } from "../../../../../../../../lib/remediation-work-input";
import { compareStoredIntegrityCaptureIds } from "../../../../../../../../lib/work-integrity-persistent-comparisons";

type Props = { params: Promise<{ slug: string; captureId: string; afterId: string }> };
export default async function IntegrityCaptureComparison({ params }: Props) {
  const { slug, captureId, afterId } = await params;
  const { membership } = await requireOrganizationAccess(slug);
  if (!canReadWork(membership.role)) notFound();
  if (![captureId, afterId].every(id => /^[a-zA-Z0-9_-]{5,100}$/.test(id))) notFound();
  const comparison = await compareStoredIntegrityCaptureIds(
    membership.organization.id, captureId, afterId,
  ).catch(() => null);
  if (!comparison) notFound();
  const base = `/organizations/${encodeURIComponent(slug)}/actions/integrity`;
  return <main className="shell"><section className="dashboard">
    <p className="eyebrow">CyberPilot · Evidence comparison</p>
    <h1 className="dashboard-title">Recorded case changes</h1>
    <p><Link href={base}>Back to history</Link></p>
    <p>Before: <Link href={`${base}/${encodeURIComponent(captureId)}`}>{comparison.beforeCapturedAt}</Link></p>
    <p>After: <Link href={`${base}/${encodeURIComponent(afterId)}`}>{comparison.afterCapturedAt}</Link></p>
    <p>{comparison.complete ? "Both captures declare complete coverage." :
      "Incomplete evidence: absent cases must remain indeterminate."}</p>
    <dl>{Object.entries(comparison.counts).map(([kind, count]) =>
      <div key={kind}><dt>{kind}</dt><dd>{count}</dd></div>)}</dl>
    <h2>Case-level changes</h2>
    {comparison.deltas.length === 0 ? <p>No cases recorded in either capture.</p> :
      <table><thead><tr><th>Classification</th><th>Case</th><th>Changes</th><th>Diagnostic</th></tr></thead>
        <tbody>{comparison.deltas.map(delta => {
          const item = delta.after ?? delta.before;
          return <tr key={delta.key}>
            <td>{delta.kind}</td>
            <td><code>{item?.code}</code><p>{item?.resourceId}</p><p>Work: {item?.workItemId}</p></td>
            <td>{delta.changes.length ? delta.changes.join(", ") : "—"}</td>
            <td>{delta.after?.diagnostic ?? delta.before?.diagnostic ?? "Not recorded"}</td>
          </tr>;
        })}</tbody></table>}
    <h2>Interpretation limits</h2>
    {comparison.warnings.map(warning => <p key={warning}>{warning}</p>)}
    <p><Link href={`/organizations/${encodeURIComponent(slug)}/actions/work`}>Coordinate remediation work</Link></p>
  </section></main>;
}
