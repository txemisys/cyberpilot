import Link from "next/link";
import { requireOrganizationAccess } from "../../../../../lib/organizations";
import { canReadWork } from "../../../../../lib/remediation-work-input";
import { pageStoredIntegrityCaptures } from "../../../../../lib/work-integrity-persistent-captures";
import { compareLatestStoredIntegrityCaptures } from "../../../../../lib/work-integrity-persistent-comparisons";

type Props = {
  params: Promise<{ slug: string }>;
  searchParams: Promise<{ source?: string; cursor?: string }>;
};
export default async function IntegrityHistoryPage({ params, searchParams }: Props) {
  const { slug } = await params;
  const query = await searchParams;
  const { membership } = await requireOrganizationAccess(slug);
  const base = `/organizations/${encodeURIComponent(slug)}/actions/integrity`;
  if (!canReadWork(membership.role))
    return <main className="shell"><h1>Integrity history</h1><p>Access denied.</p></main>;
  const source = typeof query.source === "string" && query.source.trim() ?
    query.source.slice(0, 1000) : undefined;
  const cursor = typeof query.cursor === "string" ? query.cursor : undefined;
  let page: Awaited<ReturnType<typeof pageStoredIntegrityCaptures>> | null = null;
  let comparison: Awaited<ReturnType<typeof compareLatestStoredIntegrityCaptures>> = null;
  let error: string | null = null;
  try {
    page = await pageStoredIntegrityCaptures(membership.organization.id, 30, cursor, source);
    if (source && !cursor)
      comparison = await compareLatestStoredIntegrityCaptures(membership.organization.id, source);
  } catch {
    error = "The requested history could not be loaded. Check the source or cursor.";
  }
  const historyUrl = (nextCursor?: string) => {
    const query = new URLSearchParams();
    if (source) query.set("source", source);
    if (nextCursor) query.set("cursor", nextCursor);
    return `${base}${query.size ? `?${query}` : ""}`;
  };
  return (
    <main className="shell">
      <section className="dashboard">
        <p className="eyebrow">CyberPilot · Integrity</p>
        <h1 className="dashboard-title">Stored diagnostic history</h1>
        <p className="lede">{membership.organization.name} · Historical observations, not independently verified security outcomes.</p>
        <p className="action-link"><Link href={`/organizations/${slug}/actions`}>Back to action center</Link></p>
        <form method="get" action={base}>
          <label htmlFor="source">Capture source</label>
          <input id="source" name="source" defaultValue={source ?? ""} maxLength={1000}
            placeholder="All sources" />
          <button type="submit">Filter history</button>
          <Link href={base}>Clear filter</Link>
        </form>
        {error && <p role="alert">{error}</p>}
        {comparison && <section aria-label="Latest capture comparison">
          <h2>Latest comparison · {comparison.source}</h2>
          <p><Link href={`${base}/${encodeURIComponent(comparison.before.id)}/compare/${encodeURIComponent(comparison.after.id)}`}>Inspect individual case changes</Link></p>
          <p>From {comparison.before.capturedAt} to {comparison.after.capturedAt}</p>
          <p>{comparison.comparison.complete ? "Both captures declare complete coverage." :
            "Coverage is incomplete; missing cases are indeterminate."}</p>
          <dl>
            {Object.entries(comparison.comparison.counts).map(([kind, count]) =>
              <div key={kind}><dt>{kind}</dt><dd>{count}</dd></div>)}
          </dl>
          {comparison.comparison.warnings.map(warning =>
            <p key={warning}>{warning}</p>)}
        </section>}
        {page && <section aria-label="Stored captures">
          <h2>Capture records</h2>
          {page.captures.length === 0 ? <p>No captures found for this selection.</p> :
            <table><thead><tr><th>Source</th><th>Captured</th><th>Cases</th><th>Coverage</th><th>Digest</th></tr></thead>
              <tbody>{page.captures.map(item => <tr key={item.id}>
                <td><Link href={historyUrl().split("?")[0] + "?source=" + encodeURIComponent(item.source)}>{item.source}</Link></td>
                <td><Link href={`${base}/${encodeURIComponent(item.id)}`}>{item.capturedAt}</Link></td><td>{item.caseCount}</td>
                <td>{item.complete ? "Declared complete" : "Incomplete"}</td>
                <td><code title={item.digest}>{item.digest.slice(0, 12)}…</code></td>
              </tr>)}</tbody></table>}
          {page.nextCursor && <p><Link href={historyUrl(page.nextCursor)}>Older captures</Link></p>}
        </section>}
        <p>Stored hashes check consistency of recorded data, not its original provenance.</p>
        <p>A case disappearing from incomplete evidence does not prove remediation.</p>
      </section>
    </main>
  );
}
