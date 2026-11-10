"use client";

import { useEffect, useState } from "react";

type RotationKey = {
  id: string; organizationId: string;
  state: "ACTIVE" | "RETIRING" | "REVOKED";
  notBefore: string | null; notAfter: string | null;
  currentlyAccepting: boolean;
  acceptsAtActivation: boolean; acceptsAtRetirement: boolean;
  expiresSoon: boolean; validInterval: boolean;
  weakSchedule: boolean; observations: string[];
};
type Inventory = {
  schema: string; organizationId: string; examinedAt: string;
  configured: boolean; keyCount: number; activeKeyCount: number;
  retiringKeyCount: number; revokedKeyCount: number;
  keys: RotationKey[]; secretsExposed: false; warnings: string[];
};
type RotationPlan = {
  schema: string; organizationId: string; generatedAt: string;
  retiringKeyId: string; replacingKeyId: string;
  effectiveAt: string; retireAt: string;
  keyCount: number; keysForTenant: RotationKey[];
  activeAtEffective: number; activeAtRetirement: number;
  overlappingMinutes: number; outstandingClaims: number;
  unsettledQuotas: number; recentAcceptedNonces: number;
  readyForOperatorReview: boolean;
  warnings: string[]; blockingReasons: string[];
  previewDigest: string; secretsExposed: false;
  changesApplied: false;
};
type DryRun = {
  schema: string; organizationId: string;
  evaluatedAt: string; before: Inventory; after: Inventory;
  plan: RotationPlan; proposedConfigurationDigest: string;
  noSecretsOrConfigWritten: true;
  rolloutStages: Array<{
    stage: "PREPARE" | "VERIFY" | "OVERLAP" | "RETIRE" | "REVOKE";
    requiresHumanApproval: true;
    instruction: string; rollbackConsideration: string;
  }>;
};
function errorMessage(value: unknown) {
  return value instanceof Error ? value.message :
    "OSV key rotation assessment unavailable.";
}
function date(value: string | null) {
  if (!value) return "Unbounded";
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ?
    parsed.toLocaleString() : "Invalid configured time";
}
async function read<T>(url: string, method: "GET" | "POST",
  payload?: unknown): Promise<T> {
  const res = await fetch(url, {
    method, credentials: "same-origin", cache: "no-store",
    headers: method === "GET" ? {
      Accept: "application/json",
    } : {
      Accept: "application/json", "Content-Type": "application/json",
    },
    ...(method === "POST" ? { body: JSON.stringify(payload) } : {}),
  });
  const data: unknown = await res.json();
  if (!res.ok) {
    const cause = data as { error?: string };
    throw new Error(cause.error ??
      "OSV rotation HTTP " + res.status);
  }
  return data as T;
}
function Counter({ label, value }: {
  label: string; value: number;
}) {
  return <div style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 10,
  }}><strong>{value}</strong><p>{label}</p></div>;
}
function KeyRow({ value }: { value: RotationKey }) {
  return <article style={{
    border: "1px solid #8885", borderRadius: 8,
    padding: 12, marginBlock: 8,
  }}>
    <strong>{value.id} · {value.state}</strong>
    <p>Current acceptance: {value.currentlyAccepting ?
      "YES" : "NO"}. Scheduled validity:
      {" "}{date(value.notBefore)} – {date(value.notAfter)}.</p>
    <p>Accepts at activation: {value.acceptsAtActivation ? "YES" : "NO"}.
      Accepts at retirement: {value.acceptsAtRetirement ? "YES" : "NO"}.</p>
    {value.expiresSoon && <p role="alert">
      Key expiry is within the configured warning window.</p>}
    {value.observations.length > 0 &&
      <ul>{value.observations.map((reason, index) =>
        <li key={index}>{reason}</li>)}</ul>}
  </article>;
}
export function AssetOsvKeyRotationWorkspace({
  slug, organizationId, canManage,
}: {
  slug: string; organizationId: string; canManage: boolean;
}) {
  const endpoint = "/api/organizations/" +
    encodeURIComponent(slug) + "/assets/osv-key-rotation";
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [plan, setPlan] = useState<DryRun | null>(null);
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const [activation, setActivation] = useState("");
  const [retirement, setRetirement] = useState("");
  const [newNotBefore, setNewNotBefore] = useState("");
  const [newNotAfter, setNewNotAfter] = useState("");
  const [minOverlap, setMinOverlap] = useState(15);
  const [maxOverlap, setMaxOverlap] = useState(1440);
  const [maxActiveKeys, setMaxActiveKeys] = useState(2);
  const [requireCleanClaims, setRequireCleanClaims] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!canManage) return;
    let cancelled = false;
    void read<Inventory>(endpoint, "GET").then(value => {
      if (!cancelled) {
        setInventory(value); setError(null);
      }
    }).catch(cause => {
      if (!cancelled) setError(errorMessage(cause));
    });
    return () => { cancelled = true; };
  }, [canManage, endpoint, revision]);
  function resetPlan() {
    setPlan(null); setError(null);
  }
  function toIso(value: string): string | null {
    const parsed = new Date(value);
    return Number.isFinite(parsed.getTime()) ?
      parsed.toISOString() : null;
  }
  async function evaluate() {
    if (busy || !oldId.trim() || !newId.trim()) return;
    const effectiveAt = toIso(activation);
    const retireAt = toIso(retirement);
    const notBefore = toIso(newNotBefore);
    const notAfter = toIso(newNotAfter);
    if (!effectiveAt || !retireAt || !notBefore || !notAfter) {
      setError("All activation, retirement and key validity dates are required.");
      return;
    }
    setBusy(true); resetPlan();
    try {
      const result = await read<DryRun>(endpoint, "POST", {
        organizationId,
        retiringKeyId: oldId.trim(), replacingKeyId: newId.trim(),
        effectiveAt, retireAt, notBefore, notAfter,
        policy: {
          maximumActiveKeys: maxActiveKeys,
          minimumOverlapMinutes: minOverlap,
          maximumOverlapMinutes: maxOverlap,
          warningLeadHours: 72,
          requireDistinctMaterial: true,
          requireZeroOutstandingClaims: requireCleanClaims,
        },
      });
      setPlan(result);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally { setBusy(false); }
  }
  if (!canManage) return null;
  return <section aria-label="OSV HMAC key rotation readiness"
    style={{
      border: "1px solid #8885", borderRadius: 12,
      padding: 16, marginBlock: 20,
    }}>
    <h2>OSV dispatcher key rotation planning</h2>
    <p>Preview tenant-specific HMAC activation, expiry,
      retirement and revocation windows. Neither the preview
      nor this console provisions credentials, rewrites deployment
      environment variables or enables the dispatcher.</p>
    {error && <p role="alert">{error}</p>}
    {busy && <p role="status">Reviewing key windows and claims…</p>}
    {inventory && <section>
      <h3>Current credential inventory</h3>
      <p>Signed dispatch configuration:
        {" "}<strong>{inventory.configured ? "ENABLED" : "DISABLED"}</strong>.
        Last inspected: {date(inventory.examinedAt)}.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Counter label="Tenant key IDs"
          value={inventory.keyCount}/>
        <Counter label="Currently accepting"
          value={inventory.activeKeyCount}/>
        <Counter label="Retiring keys"
          value={inventory.retiringKeyCount}/>
        <Counter label="Revoked keys"
          value={inventory.revokedKeyCount}/>
      </div>
      {inventory.keys.map(key =>
        <KeyRow key={key.id} value={key}/>)}
    </section>}
    <fieldset disabled={busy}>
      <legend>Evaluate a proposed overlapping cutover</legend>
      <p>Enter only key identifiers and dates. Never paste HMAC
        secrets, signed requests or access tokens into this form.</p>
      <label>Retiring key ID
        <input maxLength={100} value={oldId}
          onChange={event => {
            setOldId(event.target.value); resetPlan();
          }}/>
      </label>
      <label>Replacement key ID
        <input maxLength={100} value={newId}
          onChange={event => {
            setNewId(event.target.value); resetPlan();
          }}/>
      </label>
      <div style={{
        display: "grid", gap: 12,
        gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))",
      }}>
        <label>Cutover activation (local time)
          <input type="datetime-local" value={activation}
            onChange={event => {
              setActivation(event.target.value); resetPlan();
            }}/>
        </label>
        <label>Retire old key (local time)
          <input type="datetime-local" value={retirement}
            onChange={event => {
              setRetirement(event.target.value); resetPlan();
            }}/>
        </label>
        <label>New key valid from
          <input type="datetime-local" value={newNotBefore}
            onChange={event => {
              setNewNotBefore(event.target.value); resetPlan();
            }}/>
        </label>
        <label>New key expires
          <input type="datetime-local" value={newNotAfter}
            onChange={event => {
              setNewNotAfter(event.target.value); resetPlan();
            }}/>
        </label>
      </div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <label>Minimum overlap (minutes)
          <select value={minOverlap}
            onChange={event => {
              setMinOverlap(Number(event.target.value)); resetPlan();
            }}>
            {[1, 15, 30, 60, 120].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum overlap (minutes)
          <select value={maxOverlap}
            onChange={event => {
              setMaxOverlap(Number(event.target.value)); resetPlan();
            }}>
            {[30, 60, 120, 360, 1440, 10080].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label>Maximum simultaneously active keys
          <select value={maxActiveKeys}
            onChange={event => {
              setMaxActiveKeys(Number(event.target.value)); resetPlan();
            }}>
            {[2, 3, 4, 5].map(n =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <label>
        <input type="checkbox" checked={requireCleanClaims}
          onChange={event => {
            setRequireCleanClaims(event.target.checked); resetPlan();
          }}/>
        Block approval while claims or quota reservations
        remain unsettled
      </label>
      <button type="button" disabled={busy || !oldId.trim() ||
        !newId.trim() || !activation || !retirement ||
        !newNotBefore || !newNotAfter}
        onClick={() => void evaluate()}>
        Evaluate rotation without changing credentials
      </button>
      <button type="button" disabled={busy}
        onClick={() => setRevision(n => n + 1)}>
        Reload configured key IDs
      </button>
    </fieldset>
    {plan && <section>
      <h3>Rotation assessment</h3>
      <p>Operator review: <strong>{
        plan.plan.readyForOperatorReview ? "ELIGIBLE" : "BLOCKED"
      }</strong>. Changes applied: <strong>No</strong>.
        Secrets exposed: <strong>No</strong>.</p>
      <div style={{
        display: "grid", gap: 8,
        gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))",
      }}>
        <Counter label="Active at activation"
          value={plan.plan.activeAtEffective}/>
        <Counter label="Active after cutover"
          value={plan.plan.activeAtRetirement}/>
        <Counter label="Overlap minutes"
          value={plan.plan.overlappingMinutes}/>
        <Counter label="Unsettled claims"
          value={plan.plan.outstandingClaims}/>
        <Counter label="Unsettled quota"
          value={plan.plan.unsettledQuotas}/>
        <Counter label="Accepted nonces in last day"
          value={plan.plan.recentAcceptedNonces}/>
      </div>
      {plan.plan.blockingReasons.length > 0 && <section role="alert">
        <h4>Rotation blockers</h4>
        <ul>{plan.plan.blockingReasons.map((reason, index) =>
          <li key={index}>{reason}</li>)}</ul>
      </section>}
      <h4>Proposed tenant key state</h4>
      {plan.after.keys.map(key =>
        <KeyRow key={key.id} value={key}/>)}
      <h4>Human-approved deployment stages</h4>
      {plan.rolloutStages.map(item =>
        <article key={item.stage} style={{
          border: "1px solid #8885",
          borderRadius: 8, marginBlock: 8, padding: 10,
        }}>
          <strong>{item.stage}</strong>
          <p>{item.instruction}</p>
          <p>Rollback and failure considerations:
            {" "}{item.rollbackConsideration}</p>
        </article>)}
      <details>
        <summary>Rotation plan fingerprints and boundaries</summary>
        <p>Plan fingerprint:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {plan.plan.previewDigest}</code></p>
        <p>Proposed key-metadata fingerprint:
          {" "}<code style={{ overflowWrap: "anywhere" }}>
            {plan.proposedConfigurationDigest}</code></p>
        <ul>{plan.plan.warnings.map((warning, index) =>
          <li key={index}>{warning}</li>)}</ul>
      </details>
    </section>}
  </section>;
}
