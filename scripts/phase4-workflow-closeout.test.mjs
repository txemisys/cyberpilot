import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  CLOSEOUT_SCHEMA, REQUIRED_WORKFLOWS, REQUIRED_CI_STEPS,
  CLOSEOUT_LIMITATIONS, parseCloseoutOptions,
  reconcileWorkflowRuns, verifyPrHead, validateCiJobSteps,
  createCloseoutVerdict, verifyCloseoutVerdict,
  githubJsonClient, createCloseoutFetcher, inspectGitHubCloseout,
  intervalPolicy, pollCloseout,
} from "./phase4-workflow-closeout.mjs";

const head = "a".repeat(40);
const other = "b".repeat(40);
const repo = "txemisys/cyberpilot";
const number = 211;
const options = { repo, prNumber: number, commitSha: head,
  maxAttempts: 3, retrySeconds: 1 };
function run(name, id, changes = {}) {
  return {
    name, id, head_sha: head, event: "pull_request",
    status: "completed", conclusion: "success",
    html_url: `https://github.com/txemisys/cyberpilot/actions/runs/${id}`,
    run_attempt: 1, created_at: "2026-11-12T10:00:00Z",
    updated_at: "2026-11-12T10:01:00Z", ...changes,
  };
}
function runs() {
  return REQUIRED_WORKFLOWS.map((name, index) => run(name, 100 + index));
}
function pr(changes = {}) {
  return {
    number, state: "open", merged: false, draft: true,
    mergeable: true, head: { sha: head },
    base: { ref: "main" }, ...changes,
  };
}
function jobs(changes = {}) {
  return [{ id: 400, name: "verify", steps: [
    { name: "Checkout", status: "completed", conclusion: "success" },
    ...REQUIRED_CI_STEPS.map(name => ({
      name, status: "completed", conclusion: "success",
    })),
  ], ...changes }];
}
function fetcher(r = runs(), p = pr(), j = jobs()) {
  return {
    async pr() { return p; },
    async runs() { return r; },
    async ciJobs() { return j; },
  };
}
function proof() {
  const workflows = reconcileWorkflowRuns(runs(), head);
  const ciSteps = validateCiJobSteps(jobs());
  const prHead = verifyPrHead(pr(), head, number);
  return createCloseoutVerdict({
    repo, prNumber: number, commitSha: head,
    evaluatedAt: "2026-11-12T10:01:00Z",
    actionRunId: 1234, workflows, ciSteps, prHead,
  });
}
test("Five mandatory workflows and six required CI stages are fixed", () => {
  assert.equal(REQUIRED_WORKFLOWS.length, 5);
  assert.equal(REQUIRED_CI_STEPS.length, 6);
  assert.equal(new Set(REQUIRED_WORKFLOWS).size, 5);
  assert.equal(new Set(REQUIRED_CI_STEPS).size, 6);
  assert.equal(CLOSEOUT_LIMITATIONS.length >= 6, true);
});
test("Options require exact SHA, authorized repo identity and bounded retry", () => {
  assert.deepEqual(parseCloseoutOptions(options), {
    ...options,
    targetPath: ".artifacts/phase4-workflow-closeout.json",
  });
  for (const invalid of [
    { repo: "notarepo" }, { repo: "../evil" },
    { prNumber: -1 }, { prNumber: "211" },
    { commitSha: "wrong" }, { commitSha: other.toUpperCase() },
    { maxAttempts: 0 }, { maxAttempts: 181 },
    { retrySeconds: 0 }, { retrySeconds: 61 },
    { targetPath: "../escape" }, { targetPath: "/tmp/elsewhere" },
    { targetPath: "evidence.json" }, { mergeAuthorized: true },
  ]) assert.throws(() => parseCloseoutOptions({
    ...options, ...invalid,
  }));
});
test("All five concluded success on exact commit are accepted", () => {
  const outcome = reconcileWorkflowRuns(runs(), head);
  assert.equal(outcome.valid, true);
  assert.equal(outcome.workflows.length, 5);
  assert.deepEqual(outcome.pending, []);
  assert.deepEqual(outcome.failed, []);
  assert.deepEqual(outcome.missing, []);
  assert.equal(outcome.approvalsVerified, false);
});
test("Different SHA results are ignored, including a green main commit", () => {
  const outcome = reconcileWorkflowRuns(runs().map(r => ({
    ...r, head_sha: other,
  })), head);
  assert.equal(outcome.valid, false);
  assert.equal(outcome.missing.length, 5);
  assert.equal(outcome.ignoredRuns, 5);
});
test("A green push to main cannot substitute for a PR workflow", () => {
  const outcome = reconcileWorkflowRuns(runs().map(r => ({
    ...r, event: "push",
  })), head);
  assert.equal(outcome.valid, false);
  assert.deepEqual(new Set(outcome.missing), new Set(REQUIRED_WORKFLOWS));
});
test("One unsuccessful mandatory workflow blocks the closeout", () => {
  for (const conclusion of ["failure", "cancelled", "skipped",
    "timed_out", "action_required"]) {
    const outcomes = reconcileWorkflowRuns([
      ...runs().slice(0, 4),
      run(REQUIRED_WORKFLOWS[4], 104, { conclusion }),
    ], head);
    assert.equal(outcomes.valid, false);
    assert.equal(outcomes.failed.length, 1);
  }
});
test("Queued CI must not be mistaken for all-workflow completion", () => {
  const outcome = reconcileWorkflowRuns([
    ...runs().slice(0, 4),
    run(REQUIRED_WORKFLOWS[4], 104, {
      status: "queued", conclusion: null,
    }),
  ], head);
  assert.equal(outcome.valid, false);
  assert.deepEqual(outcome.pending, ["Backup restore rehearsal"]);
});
test("Newer failure supersedes an older success on same SHA", () => {
  const outcome = reconcileWorkflowRuns([
    ...runs(), run("CI", 999, { conclusion: "failure" }),
  ], head);
  assert.equal(outcome.valid, false);
  assert.equal(outcome.failed[0].name, "CI");
  assert.equal(outcome.supersededRunCount, 1);
});
test("Newest successful rerun supersedes an older failure", () => {
  const outcome = reconcileWorkflowRuns([
    ...runs(), run("CI", 1000),
    run("CI", 99, { conclusion: "failure" }),
  ], head);
  assert.equal(outcome.valid, true);
  assert.equal(outcome.workflows.find(x => x.name === "CI").id, 1000);
});
test("Unknown workflows and malformed entries never add fake evidence", () => {
  const outcome = reconcileWorkflowRuns([
    ...runs(), { name: "Fake", id: 500, head_sha: head },
    { name: "Security", id: null, head_sha: head },
  ], head);
  assert.equal(outcome.valid, true);
  assert.equal(outcome.ignoredRuns, 2);
});
test("PR HEAD changes, closed state and wrong PR number block closure", () => {
  assert.equal(verifyPrHead(pr(), head, number).valid, true);
  assert.equal(verifyPrHead(pr({ head: { sha: other } }),
    head, number).valid, false);
  assert.equal(verifyPrHead(pr({ state: "closed" }),
    head, number).valid, false);
  assert.equal(verifyPrHead(pr({ merged: true }),
    head, number).valid, false);
  assert.equal(verifyPrHead(pr(), head, 999).valid, false);
});
test("Draft is not itself a technical failure", () => {
  const outcome = verifyPrHead(pr({ draft: true }), head, number);
  assert.equal(outcome.valid, true);
  assert.equal(outcome.draft, true);
  assert.equal(outcome.mergeable, true);
});
test("Six mandatory CI stages must pass once each", () => {
  const outcome = validateCiJobSteps(jobs());
  assert.equal(outcome.valid, true);
  assert.equal(outcome.steps.length, 6);
  assert.equal(outcome.buildAfterGate, true);
  assert.equal(outcome.testsBeforeGate, true);
});
test("Missing, duplicated or failed CI step is a failure", () => {
  const base = jobs();
  for (const target of REQUIRED_CI_STEPS) {
    const missing = validateCiJobSteps([{
      ...base[0],
      steps: base[0].steps.filter(s => s.name !== target),
    }]);
    assert.equal(missing.valid, false);
    const failed = validateCiJobSteps([{
      ...base[0],
      steps: base[0].steps.map(s => s.name === target ?
        { ...s, conclusion: "failure" } : s),
    }]);
    assert.equal(failed.valid, false);
    const duplicated = validateCiJobSteps([{
      ...base[0],
      steps: [...base[0].steps, base[0].steps.find(s =>
        s.name === target)],
    }]);
    assert.equal(duplicated.valid, false);
  }
});
test("Acceptance gate must happen after tests and before production build", () => {
  const reversed = jobs();
  reversed[0].steps.reverse();
  assert.equal(validateCiJobSteps(reversed).valid, false);
});
test("A complete proof generates an unsigned and verifiable digest", () => {
  const verdict = proof();
  assert.equal(verdict.schema, CLOSEOUT_SCHEMA);
  assert.equal(verdict.result, "DEVELOPMENT_ACCEPTANCE_AUTOMATION_PASS");
  assert.equal(verdict.developmentReadyToConsiderMerge, true);
  assert.equal(verdict.humanAcceptanceVerified, false);
  assert.equal(verdict.externalLiveProviderVerified, false);
  assert.equal(verdict.productCustomerAcceptanceVerified, false);
  assert.equal(verdict.legalApprovalVerified, false);
  assert.equal(verdict.backupDeletionVerified, false);
  assert.equal(verdict.githubApiWrites, 0);
  assert.equal(verdict.approvedGithubMerge, false);
  assert.equal(verdict.mergedByThisWorkflow, false);
  assert.equal(verifyCloseoutVerdict(verdict).valid, true);
});
test("Cannot create positive verdict with one missing workflow", () => {
  const incomplete = reconcileWorkflowRuns(runs().slice(1), head);
  assert.throws(() => createCloseoutVerdict({
    repo, prNumber: number, commitSha: head,
    evaluatedAt: "2026-11-12T10:00:00Z",
    actionRunId: 1234,
    workflows: incomplete,
    ciSteps: validateCiJobSteps(jobs()),
    prHead: verifyPrHead(pr(), head, number),
  }));
});
test("Tampering and false business authorization are independently caught", () => {
  for (const change of [
    { operationalDeploymentApproval: true },
    { humanAcceptanceVerified: true },
    { legalApprovalVerified: true },
    { mergedByThisWorkflow: true },
    { approvedGithubMerge: true },
    { githubApiWrites: 1 },
    { securityExternallyCertified: true },
    { privacyOrRiskProtectionsDisabled: true },
  ]) {
    const verdict = { ...proof(), ...change };
    assert.equal(verifyCloseoutVerdict(verdict).valid, false);
  }
});
test("A fake SHA is rejected even when the attacker recomputes digest", () => {
  const verdict = proof();
  verdict.workflowEvidence[0].headSha = other;
  const canonical = { ...verdict };
  delete canonical.digest;
  const newHash = createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
  verdict.digest = newHash;
  assert.equal(verifyCloseoutVerdict(verdict).valid, false);
});
test("Source credentials are required and GitHub client never writes", () => {
  assert.throws(() => githubJsonClient({
    token: "", repositoryName: repo,
  }));
  assert.throws(() => githubJsonClient({
    token: "read-only-token", repositoryName: repo,
    apiRoot: "https://attacker.invalid",
  }));
});
test("GitHub reads use GET-only headers, no unexpected redirect", async () => {
  const seen = [];
  const read = githubJsonClient({
    token: "read-only-token", repositoryName: repo,
    fetchImpl: async (url, opts) => {
      seen.push({ url: String(url), opts });
      return { ok: true, json: async () => ({ workflow_runs: [] }) };
    },
  });
  const result = await read("/repos/txemisys/cyberpilot/actions/runs");
  assert.deepEqual(result, { workflow_runs: [] });
  assert.equal(seen[0].opts.method, "GET");
  assert.equal(seen[0].opts.redirect, "error");
  await assert.rejects(() => read("../evil"), /Unsafe GitHub read path/);
});
test("GitHub fetcher uses only exact repository and SHA paths", async () => {
  const requested = [];
  const fetcher = createCloseoutFetcher(async path => {
    requested.push(path);
    if (path.includes("/pulls/")) return pr();
    if (path.includes("/jobs?")) return { jobs: jobs(),
      total_count: 1 };
    return { workflow_runs: runs(), total_count: 5 };
  }, repo);
  assert.equal((await fetcher.pr(number)).number, number);
  assert.equal((await fetcher.runs(head)).length, 5);
  assert.equal((await fetcher.ciJobs(100)).length, 1);
  assert.equal(requested.every(x => x.startsWith("/repos/" + repo)),
    true);
});
test("Read-only closeout verifies complete simulated GitHub evidence", async () => {
  const result = await inspectGitHubCloseout(fetcher(), options);
  assert.equal(result.complete, true);
  assert.equal(result.ciSteps.valid, true);
  assert.equal(result.prHead.valid, true);
  assert.equal(result.workflows.valid, true);
});
test("Poller returns after first complete evaluation", async () => {
  const progress = [];
  const result = await pollCloseout(fetcher(), options, {
    sleep: async () => { throw new Error("Should not wait."); },
    onProgress: info => progress.push(info),
  });
  assert.equal(result.complete, true);
  assert.equal(progress.length, 1);
});
test("Poller waits for a delayed required workflow without faking status", async () => {
  let attempts = 0;
  let slept = 0;
  const engine = fetcher();
  engine.runs = async () => {
    attempts++;
    return attempts < 2 ? runs().slice(1) : runs();
  };
  const result = await pollCloseout(engine, options, {
    sleep: async () => { slept++; },
  });
  assert.equal(result.complete, true);
  assert.equal(attempts, 2);
  assert.equal(slept, 1);
});
test("Failed workflow stops polling and gives an actionable error", async () => {
  const bad = fetcher([
    ...runs().slice(0, 4),
    run("Backup restore rehearsal", 104, { conclusion: "failure" }),
  ]);
  await assert.rejects(() => pollCloseout(bad, options, {
    sleep: async () => {},
  }), /workflow failed/);
});
test("Missing workflow never silently passes after bounded retries", async () => {
  let iterations = 0;
  const bad = fetcher(runs().slice(1));
  await assert.rejects(() => pollCloseout(bad, options, {
    sleep: async () => { iterations++; },
  }), /Timed out/);
  assert.equal(iterations, 2);
});
test("Current GitHub HEAD must match the workflow commit", async () => {
  await assert.rejects(() => inspectGitHubCloseout(
    fetcher(runs(), pr({ head: { sha: other } })), options),
  /PR identity changed/);
});
test("Interval policy is bounded and independently reproducible", () => {
  assert.deepEqual(intervalPolicy(options), {
    attempts: 3, intervalMilliseconds: 1000,
    theoreticalMaxWaitSeconds: 2,
  });
});
