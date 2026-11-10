"use client";

import { useMemo, useState } from "react";

type PrivacyGate = {
  id: string;
  severity: "PASS" | "BLOCK" | "REVIEW";
  message: string; observed: number; target: number | null;
  affectedImportIds: string[]; rationale: string;
};
type Import = {
  importId: string; state: string;
  ageDays: number; retiredDays: number | null;
  sourceDigest: string; declaredDeviceCount: number;
  verifiedDeviceCount: number; hostnameCount: number;
  ownerHashCount: number; linkedInspectionCount: number;
  linkedCaseCount: number; linkedScheduleCount: number;
  openCaseCount: number; oldestOpenCaseAgeDays: number | null;
  oldestInspectionAgeDays: number | null;
  eligibleForSeparatePurgePreview: boolean;
  blockers: string[]; recommendations: string[];
  possiblePersonalData: boolean;
  dataProvenance: "CUSTOMER_DECLARED_CSV";
};
type Procedure = {
  stage: string; requiresHumanApproval: true;
  instruction: string; evidenceToRetain: string;
  destructive: boolean;
};
type PrivacyReport = {
  schema: string; organizationId: string; evaluatedAt: string;
  importedCount: number; fullyExamined: boolean;
  totalDeviceCount: number; totalPotentialHostnames: number;
  totalOwnerHashes: number; totalLinkedInspections: number;
  totalLinkedCases: number; totalLinkedSchedules: number;
  auditRecords: number; auditWithUser: number;
  auditWithResource: number; recordsWithPiiSignals: number;
  activeTooOld: number; retiredMatured: number;
  openCasesBeyondPolicy: number;
  gates: PrivacyGate[]; imports: Import[];
  readiness: {
    blocked: number; reviewNeeded: number; passed: number;
    pendingOperatorApproval: boolean;
    eligibleForPrivacySignoff: boolean;
  };
  procedure: Procedure[]; digest: string;
  databasesMutated: false; personalDataErased: false;
  backupDeletionVerified: false; userConsentInferred: false;
  warnings: string[];
};
function when(iso: string) {
  const date = new Date(iso);
  return Number.isFinite(date.getTime()) ?
    date.toLocaleString() : "Invalid evaluation date";
}
function err(value: unknown) {
  return value instanceof Error ? value.message :
    "Privacy readiness report could not be completed.";
}
function Stat({ label, value }: {
  label: string; value: number;
}) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8, padding: 10,
  }}>
    <strong>{value}</strong><p>{label}</p>
  </div>;
}
function Gate({ gate }: { gate: PrivacyGate }) {
  const [open, setOpen] = useState(false);
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{gate.severity} · {gate.id}</strong>
    <p>{gate.message}</p>
    <p>Observed: {gate.observed}.
      Threshold: {gate.target === null ? "operator-defined" :
        gate.target}.</p>
    <button type="button" onClick={() => setOpen(x => !x)}>
      {open ? "Hide" : "Explain"} privacy gate
    </button>
    {open && <>
      <p>{gate.rationale}</p>
      {gate.affectedImportIds.length > 0 &&
        <details>
          <summary>Related inventory IDs</summary>
          <ul>{gate.affectedImportIds.map(id =>
            <li key={id}><code>{id}</code></li>)}</ul>
        </details>}
    </>}
  </article>;
}
function ImportCard({ item }: { item: Import }) {
  const [expanded, setExpanded] = useState(false);
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    marginBlock: 8, padding: 12,
  }}>
    <strong>{item.state} · {item.importId}</strong>
    <p>Snapshot age: {item.ageDays} days.
      Retired: {item.retiredDays === null ?
        "not retired" : item.retiredDays + " days ago"}.</p>
    <p>Devices: {item.verifiedDeviceCount} /
      {" "}{item.declaredDeviceCount}.
      Hostnames: {item.hostnameCount}.
      Owner hashes: {item.ownerHashCount}.</p>
    <p>Stored inspections: {item.linkedInspectionCount}.
      Human review cases: {item.linkedCaseCount}.
      Scheduled renewals: {item.linkedScheduleCount}.</p>
    <p>Separate purge preview:
      {" "}<strong>{item.eligibleForSeparatePurgePreview ?
        "AGE-ELIGIBLE (NOT APPROVED)" : "NOT ELIGIBLE"}</strong>.
    </p>
    <button type="button" onClick={() =>
      setExpanded(x => !x)}>
      {expanded ? "Hide" : "Review"} personal data and dependencies
    </button>
    {expanded && <>
      <p>Possible personal data:
        {" "}{item.possiblePersonalData ? "YES" : "NOT CONFIRMED"}.
        Source: {item.dataProvenance}.</p>
      <p>Open reviews: {item.openCaseCount}.
        Oldest open review age:
        {" "}{item.oldestOpenCaseAgeDays ?? "unknown"} days.</p>
      <p>Oldest OSV inspection age:
        {" "}{item.oldestInspectionAgeDays ?? "unknown"} days.</p>
      <p>Source SHA-256:
        {" "}<code style={{ overflowWrap: "anywhere" }}>
          {item.sourceDigest}</code></p>
      {item.blockers.length > 0 && <div role="alert">
        <strong>Destructive-operation blockers</strong>
        <ul>{item.blockers.map((text, index) =>
          <li key={index}>{text}</li>)}</ul>
      </div>}
      <strong>Operator investigations</strong>
      <ol>{item.recommendations.map((text, index) =>
        <li key={index}>{text}</li>)}</ol>
    </>}
  </article>;
}
const defaults = {
  minimumRetiredDays: 30,
  maximumCandidateAgeDays: 365,
  maximumActiveAgeDays: 365,
  maximumEvidenceAgeDays: 365,
  maximumOpenCaseAgeDays: 90,
  maxImports: 100,
  requireBackupDeletionProcedure: true,
  requireOwnerHashDisposalReview: true,
  requireHostnameReview: true,
  requireCaseDataRetentionReview: true,
};
export function AssetPrivacyReadinessWorkspace({
  slug, canManage,
}: { slug: string; canManage: boolean }) {
  const url = "/api/organizations/" + encodeURIComponent(slug) +
    "/assets/privacy-readiness";
  const [policy, setPolicy] = useState(defaults);
  const [report, setReport] = useState<PrivacyReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPassed, setShowPassed] = useState(false);
  const [onlyRelevant, setOnlyRelevant] = useState(false);
  const [filter, setFilter] = useState("");
  const [showProcedure, setShowProcedure] = useState(false);
  const [copied, setCopied] = useState(false);
  const gates = useMemo(() =>
    report?.gates.filter(gate =>
      showPassed || gate.severity !== "PASS") ?? [],
  [showPassed, report]);
  const imports = useMemo(() =>
    report?.imports.filter(row =>
      (!onlyRelevant || row.blockers.length > 0 ||
        row.recommendations.length > 0) &&
      (!filter.trim() || row.importId.toLowerCase().includes(
        filter.trim().toLowerCase()))) ?? [],
  [report, onlyRelevant, filter]);
  function updateNumber(name:
    "minimumRetiredDays" | "maximumCandidateAgeDays" |
    "maximumActiveAgeDays" | "maximumEvidenceAgeDays" |
    "maximumOpenCaseAgeDays" | "maxImports", value: number) {
    setPolicy(old => ({ ...old, [name]: value }));
    setReport(null);
  }
  function updateBoolean(name:
    "requireBackupDeletionProcedure" |
    "requireOwnerHashDisposalReview" | "requireHostnameReview" |
    "requireCaseDataRetentionReview", value: boolean) {
    setPolicy(old => ({ ...old, [name]: value }));
    setReport(null);
  }
  async function inspect() {
    if (busy) return;
    setBusy(true); setError(null); setCopied(false);
    try {
      const response = await fetch(url, {
        method: "POST", cache: "no-store",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ policy }),
      });
      const body: unknown = await response.json();
      if (!response.ok)
        throw new Error((body as { error?: string }).error ??
          "Privacy readiness HTTP " + response.status);
      const value = body as PrivacyReport;
      if (value.databasesMutated || value.personalDataErased ||
          value.backupDeletionVerified)
        throw new Error("Unexpected privacy assessment side effect.");
      setReport(value);
    } catch (cause) {
      setReport(null); setError(err(cause));
    } finally { setBusy(false); }
  }
  function copy() {
    if (!report) return;
    void navigator.clipboard.writeText(
      JSON.stringify(report, null, 2))
      .then(() => setCopied(true))
      .catch(cause => setError(err(cause)));
  }
  if (!canManage) return null;
  return <section aria-label="Asset privacy and retention readiness"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 22,
    }}>
    <h2>Assets — retention and privacy readiness</h2>
    <p>Examine the actual inventory's potential personal data,
      historical provider records, unresolved review cases,
      renewal schedules and audit references before approving
      retention or permanent deletion.</p>
    <p>This is a read-only planning tool. It does not approve
      legal policy, erase any data or verify backup deletion.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Inspecting tenant data lifecycle…</p>}
    <fieldset disabled={busy}>
      <legend>Data lifecycle and privacy policy preview</legend>
      <div style={{
        display: "grid", gap: 10,
        gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))",
      }}>
        <label>Minimum days after retirement
          <select value={policy.minimumRetiredDays}
            onChange={event =>
              updateNumber("minimumRetiredDays", Number(event.target.value))}>
            {[1, 7, 30, 60, 90, 180, 365].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum age for purge candidates
          <select value={policy.maximumCandidateAgeDays}
            onChange={event =>
              updateNumber("maximumCandidateAgeDays", Number(event.target.value))}>
            {[30, 90, 180, 365, 730, 1095].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum age of active inventory
          <select value={policy.maximumActiveAgeDays}
            onChange={event =>
              updateNumber("maximumActiveAgeDays", Number(event.target.value))}>
            {[30, 90, 180, 365, 730].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum age of saved inspections
          <select value={policy.maximumEvidenceAgeDays}
            onChange={event =>
              updateNumber("maximumEvidenceAgeDays", Number(event.target.value))}>
            {[30, 90, 180, 365, 730].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum age of open human cases
          <select value={policy.maximumOpenCaseAgeDays}
            onChange={event =>
              updateNumber("maximumOpenCaseAgeDays", Number(event.target.value))}>
            {[7, 30, 60, 90, 180, 365].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum complete import count
          <select value={policy.maxImports}
            onChange={event =>
              updateNumber("maxImports", Number(event.target.value))}>
            {[10, 25, 50, 100, 250, 500].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      {([
        ["requireBackupDeletionProcedure",
          "Require validated backup and export disposal procedure"],
        ["requireOwnerHashDisposalReview",
          "Review pseudonymous owner hashes"],
        ["requireHostnameReview",
          "Review potentially identifying hostnames"],
        ["requireCaseDataRetentionReview",
          "Review case notes and human activity retention"],
      ] as const).map(([name, label]) =>
        <label key={name}>
          <input type="checkbox" checked={policy[name]}
            onChange={event =>
              updateBoolean(name, event.target.checked)}/>
          {label}
        </label>)}
      <button type="button" onClick={() => void inspect()}>
        Assess privacy and retention readiness
      </button>
    </fieldset>
    {report && <section>
      <h3>Privacy decision readiness</h3>
      <p>Policy signoff eligibility:
        {" "}<strong>{report.readiness.eligibleForPrivacySignoff ?
          "READY FOR OPERATOR REVIEW" : "NOT READY"}</strong>.
        Independent approval remains pending.</p>
      <p>Snapshot generated: {when(report.evaluatedAt)}.
        Coverage: {report.fullyExamined ?
          "COMPLETE WITHIN TENANT DATABASE" : "INCOMPLETE"}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(140px,1fr))",
      }}>
        <Stat label="Inventory snapshots" value={report.importedCount}/>
        <Stat label="Declared device rows" value={report.totalDeviceCount}/>
        <Stat label="Hostnames present" value={report.totalPotentialHostnames}/>
        <Stat label="Owner hashes present" value={report.totalOwnerHashes}/>
        <Stat label="Linked provider inspections"
          value={report.totalLinkedInspections}/>
        <Stat label="Human review cases" value={report.totalLinkedCases}/>
        <Stat label="Renewal schedules" value={report.totalLinkedSchedules}/>
        <Stat label="Asset audit events" value={report.auditRecords}/>
        <Stat label="Blocking policy gates" value={report.readiness.blocked}/>
        <Stat label="Review gates" value={report.readiness.reviewNeeded}/>
        <Stat label="Matured retired imports" value={report.retiredMatured}/>
        <Stat label="Overdue human reviews" value={report.openCasesBeyondPolicy}/>
      </div>
      <p>No data erased. No database changes. No backup
        deletion verified. No processing consent inferred.</p>
      <h3>Data protection gates</h3>
      <label>
        <input type="checkbox" checked={showPassed}
          onChange={event => setShowPassed(event.target.checked)}/>
        Include passing checks
      </label>
      {gates.map(row =>
        <Gate key={row.id} gate={row}/>)}
      <h3>Inventory data lifecycle</h3>
      <label>Filter by inventory ID
        <input value={filter}
          onChange={event => setFilter(event.target.value)}/>
      </label>
      <label>
        <input type="checkbox" checked={onlyRelevant}
          onChange={event => setOnlyRelevant(event.target.checked)}/>
        Show only imports needing operator attention
      </label>
      <p>{imports.length} inventory snapshots displayed.</p>
      {imports.map(row => <ImportCard key={row.importId} item={row}/>)}
      <h3>Controlled disposal procedure</h3>
      <button type="button" onClick={() =>
        setShowProcedure(x => !x)}>
        {showProcedure ? "Hide" : "Show"} human-approved disposal stages
      </button>
      {showProcedure && report.procedure.map(stage =>
        <article key={stage.stage} style={{
          border: "1px solid #8885", padding: 12,
          borderRadius: 8, marginBlock: 8,
        }}>
          <strong>{stage.stage}</strong>
          <p>{stage.instruction}</p>
          <p>Evidence: {stage.evidenceToRetain}</p>
          <p>Human approval required: Yes.
            Destructive: {stage.destructive ? "YES" : "NO"}.</p>
        </article>)}
      <details>
        <summary>Readiness report fingerprint and limitations</summary>
        <p>Report SHA-256:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {report.digest}</code></p>
        <ul>{report.warnings.map((line, i) =>
          <li key={i}>{line}</li>)}</ul>
      </details>
      <button type="button" onClick={copy}>Copy privacy evidence JSON</button>
      {copied && <p role="status">Privacy assessment copied.</p>}
      <p>Exported identifiers, audit metadata and data classes may
        themselves contain sensitive operational information.
        Share only with authorized privacy and security reviewers.</p>
    </section>}
  </section>;
}
