#!/usr/bin/env node
/**
 * Independent, read-only cross-workflow verdict for Phase 4 DEVELOPMENT.
 * This tool never merges a pull request, grants operational approval,
 * authenticates external customers, or changes user/tenant state.
 *
 * Its input is GitHub's authoritative Actions and PR metadata, not a
 * self-reported JSON claiming five successful workflows.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const CLOSEOUT_SCHEMA = "cyberpilot.phase4.workflow-closeout.v1";
export const REQUIRED_WORKFLOWS = Object.freeze([
  "CI", "Security", "Local stack E2E",
  "LAB browser journey", "Backup restore rehearsal",
]);
export const REQUIRED_CI_STEPS = Object.freeze([
  "Apply database migrations",
  "Verify migration status",
  "Typecheck",
  "Test",
  "Phase 4 development acceptance gate",
  "Build",
]);
export const CLOSEOUT_LIMITATIONS = Object.freeze([
  "Verifies development automation only. No human operational acceptance implied.",
  "Synthetic tests do not attest a real customer inventory or a live provider.",
  "No third-party signature, legal decision or security certification is inferred.",
  "GitHub read-only API status does not itself authorize a merge.",
  "A future HEAD requires a fresh, independently checked verdict.",
  "No authorization to enable scanners, bypass tenant isolation or delete backups.",
  "The manifest digest has no external signature or third-party attestation.",
]);
const __filename = fileURLToPath(import.meta.url);
const repository = resolve(dirname(__filename), "..");

function isRecord(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value);
}
function int(value) {
  return Number.isSafeInteger(value) && value > 0;
}
function sha(value) {
  return typeof value === "string" && /^[0-9a-f]{40}$/.test(value);
}
function hash(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
function equal(a, b) {
  return typeof a === "string" && typeof b === "string" &&
    /^[a-f0-9]{64}$/.test(a) && /^[a-f0-9]{64}$/.test(b) &&
    timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
function repoSlug(value) {
  return typeof value === "string" &&
    /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value) &&
    value.split("/").every(part => part !== "." && part !== "..");
}
export function parseCloseoutOptions(raw = {}) {
  if (!isRecord(raw)) throw new Error("Closeout input is not an object.");
  const allowed = ["repo", "prNumber", "commitSha",
    "maxAttempts", "retrySeconds", "targetPath"];
  if (Object.keys(raw).some(key => !allowed.includes(key)))
    throw new Error("Unexpected closeout option.");
  if (!repoSlug(raw.repo))
    throw new Error("GitHub repository slug required.");
  if (!int(raw.prNumber) || raw.prNumber > 10000000)
    throw new Error("Valid pull request number required.");
  if (!sha(raw.commitSha))
    throw new Error("Exact 40-digit pull request HEAD required.");
  const maxAttempts = raw.maxAttempts ?? 90;
  const retrySeconds = raw.retrySeconds ?? 10;
  if (!int(maxAttempts) || maxAttempts > 180)
    throw new Error("Maximum polling attempts out of bounds.");
  if (!int(retrySeconds) || retrySeconds > 60)
    throw new Error("Polling interval out of bounds.");
  const targetPath = raw.targetPath ??
    ".artifacts/phase4-workflow-closeout.json";
  if (typeof targetPath !== "string" ||
      !/^\.artifacts\/[A-Za-z0-9_.-]+\.json$/.test(targetPath))
    throw new Error("Output must be a local artifacts JSON file.");
  return { repo: raw.repo, prNumber: raw.prNumber,
    commitSha: raw.commitSha, maxAttempts, retrySeconds, targetPath };
}
function runInfo(raw) {
  if (!isRecord(raw)) return null;
  if (typeof raw.name !== "string" ||
      !int(raw.id) || !sha(raw.head_sha))
    return null;
  return {
    id: raw.id, name: raw.name, headSha: raw.head_sha,
    event: typeof raw.event === "string" ? raw.event : "UNKNOWN",
    status: typeof raw.status === "string" ? raw.status : "UNKNOWN",
    conclusion: typeof raw.conclusion === "string" ?
      raw.conclusion : null,
    url: typeof raw.html_url === "string" ? raw.html_url : null,
    attempt: int(raw.run_attempt) ? raw.run_attempt : 1,
    createdAt: typeof raw.created_at === "string" ?
      raw.created_at : null,
    updatedAt: typeof raw.updated_at === "string" ?
      raw.updated_at : null,
  };
}
export function reconcileWorkflowRuns(raw, expectedSha,
  required = REQUIRED_WORKFLOWS) {
  if (!sha(expectedSha))
    throw new Error("Invalid expected commit SHA.");
  if (!Array.isArray(raw))
    throw new Error("GitHub workflow run list missing.");
  const chosen = new Map();
  const ignored = [];
  const duplicates = [];
  for (const run of raw) {
    const candidate = runInfo(run);
    if (!candidate) {
      ignored.push("MALFORMED_RUN");
      continue;
    }
    if (!required.includes(candidate.name)) {
      ignored.push("UNRELATED_WORKFLOW");
      continue;
    }
    if (candidate.headSha !== expectedSha ||
        candidate.event !== "pull_request") {
      ignored.push("WRONG_SHA_OR_EVENT");
      continue;
    }
    const previous = chosen.get(candidate.name);
    if (previous && previous.id === candidate.id) {
      if (candidate.attempt > previous.attempt)
        chosen.set(candidate.name, candidate);
      continue;
    }
    if (!previous || candidate.id > previous.id)
      chosen.set(candidate.name, candidate);
    if (previous)
      duplicates.push({ name: candidate.name,
        latestId: Math.max(previous.id, candidate.id),
        olderId: Math.min(previous.id, candidate.id) });
  }
  const workflows = required.map(name => {
    const run = chosen.get(name);
    return run ? {
      ...run,
      passed: run.status === "completed" &&
        run.conclusion === "success",
    } : {
      id: null, name, headSha: expectedSha,
      event: null, status: "MISSING", conclusion: null, url: null,
      attempt: null, createdAt: null, updatedAt: null, passed: false,
    };
  });
  const missing = workflows.filter(x => x.status === "MISSING")
    .map(x => x.name);
  const pending = workflows.filter(x => !x.passed &&
    ["queued", "in_progress", "requested", "waiting", "pending"]
      .includes(x.status)).map(x => x.name);
  const failed = workflows.filter(x => x.status === "completed" &&
    x.conclusion !== "success").map(x => ({
      name: x.name, conclusion: x.conclusion, runId: x.id,
    }));
  return {
    expectedSha, workflows, missing, pending, failed,
    valid: workflows.length === required.length &&
      missing.length === 0 && pending.length === 0 &&
      failed.length === 0 && workflows.every(x => x.passed),
    ignoredRuns: ignored.length, supersededRunCount: duplicates.length,
    coverage: "EXACT_SHA_PULL_REQUEST_RUNS_ONLY",
    approvalsVerified: false,
    liveProvidersVerified: false,
  };
}
export function verifyPrHead(raw, expectedSha, expectedNumber) {
  if (!isRecord(raw)) return {
    valid: false, reasons: ["PR API response missing."],
  };
  const reasons = [];
  if (!int(raw.number) || raw.number !== expectedNumber)
    reasons.push("Unexpected PR identity.");
  if (!isRecord(raw.head) || raw.head.sha !== expectedSha)
    reasons.push("PR HEAD moved since workflows were checked.");
  if (raw.state !== "open")
    reasons.push("Pull request is not open.");
  if (raw.merged === true)
    reasons.push("Pull request was already merged.");
  return { valid: reasons.length === 0, reasons,
    draft: raw.draft === true,
    mergeable: raw.mergeable === true,
    base: typeof raw.base?.ref === "string" ? raw.base.ref : null,
    headSha: typeof raw.head?.sha === "string" ? raw.head.sha : null,
  };
}
export function validateCiJobSteps(rawJobs) {
  if (!Array.isArray(rawJobs) || rawJobs.length === 0)
    return { valid: false, steps: [], reasons: ["No CI job evidence."] };
  const steps = [];
  for (const job of rawJobs) {
    if (!isRecord(job) || !Array.isArray(job.steps)) continue;
    for (const step of job.steps) {
      if (!isRecord(step) || typeof step.name !== "string") continue;
      steps.push({
        name: step.name,
        status: typeof step.status === "string" ? step.status : "UNKNOWN",
        conclusion: typeof step.conclusion === "string" ?
          step.conclusion : null,
      });
    }
  }
  const required = REQUIRED_CI_STEPS.map(name => {
    const found = steps.filter(x => x.name === name);
    return {
      name,
      occurrenceCount: found.length,
      passed: found.length === 1 &&
        found[0].status === "completed" &&
        found[0].conclusion === "success",
      status: found[0]?.status ?? "MISSING",
      conclusion: found[0]?.conclusion ?? null,
    };
  });
  const reasons = required.filter(x => !x.passed).map(x =>
    "Mandatory CI step incomplete: " + x.name);
  const gateStepIndex = steps.findIndex(x =>
    x.name === "Phase 4 development acceptance gate");
  const buildIndex = steps.findIndex(x => x.name === "Build");
  if (gateStepIndex < 0 || buildIndex < 0 ||
      gateStepIndex >= buildIndex)
    reasons.push("Acceptance gate must precede successful production build.");
  const testIndex = steps.findIndex(x => x.name === "Test");
  if (testIndex < 0 || testIndex >= gateStepIndex)
    reasons.push("Full tests must precede acceptance gate.");
  return { valid: reasons.length === 0, steps: required,
    reasons, buildAfterGate: gateStepIndex < buildIndex,
    testsBeforeGate: testIndex < gateStepIndex };
}
export function createCloseoutVerdict(input) {
  const { repo, prNumber, commitSha, evaluatedAt,
    workflows, ciSteps, prHead, actionRunId } = input;
  if (!repoSlug(repo) || !int(prNumber) || !sha(commitSha))
    throw new Error("Closeout metadata incomplete.");
  if (!Number.isFinite(Date.parse(evaluatedAt)))
    throw new Error("Closeout evaluation clock invalid.");
  const approved = workflows?.valid === true &&
    ciSteps?.valid === true && prHead?.valid === true;
  if (!approved)
    throw new Error("Cannot create PASS from incomplete GitHub evidence.");
  if (!int(actionRunId))
    throw new Error("Must bind report to the checker workflow run.");
  const canonical = {
    schema: CLOSEOUT_SCHEMA,
    repo, prNumber, commitSha, evaluatedAt, actionRunId,
    result: "DEVELOPMENT_ACCEPTANCE_AUTOMATION_PASS",
    scope: "PHASE_4_OFFLINE_CODE_ONLY",
    criteriaSource: "https://github.com/txemisys/cyberpilot/issues/86",
    workflowEvidence: workflows.workflows.map(x => ({
      name: x.name, id: x.id, status: x.status,
      conclusion: x.conclusion, headSha: x.headSha,
      url: x.url, attempt: x.attempt,
    })),
    ciStepEvidence: ciSteps.steps,
    exactPrHeadVerified: true,
    developmentReadyToConsiderMerge: true,
    requiresRealHumanOperatorForDevelopmentClose: false,
    humanAcceptanceVerified: false,
    operationalDeploymentApproval: false,
    externalTenantsVerified: false,
    externalLiveProviderVerified: false,
    legalApprovalVerified: false,
    backupDeletionVerified: false,
    productCustomerAcceptanceVerified: false,
    securityExternallyCertified: false,
    sourceFixturesAreCustomerEvidence: false,
    signaturesCollected: [],
    approvedGithubMerge: false,
    mergedByThisWorkflow: false,
    githubApiWrites: 0,
    privacyOrRiskProtectionsDisabled: false,
    caveats: [...CLOSEOUT_LIMITATIONS],
  };
  return { ...canonical, digest: hash(canonical) };
}
export function verifyCloseoutVerdict(raw) {
  const reasons = [];
  if (!isRecord(raw)) return {
    valid: false, reasons: ["Closeout verdict missing."],
  };
  const { digest, ...canonical } = raw;
  if (!equal(digest, hash(canonical)))
    reasons.push("Digest mismatch.");
  if (raw.schema !== CLOSEOUT_SCHEMA ||
      !repoSlug(raw.repo) || !sha(raw.commitSha))
    reasons.push("Closeout identity incorrect.");
  if (!Array.isArray(raw.workflowEvidence) ||
      raw.workflowEvidence.length !== REQUIRED_WORKFLOWS.length ||
      REQUIRED_WORKFLOWS.some(name =>
        raw.workflowEvidence.filter(x => x.name === name &&
          x.headSha === raw.commitSha &&
          x.status === "completed" &&
          x.conclusion === "success").length !== 1))
    reasons.push("Not all five workflows succeeded at identical HEAD.");
  if (!Array.isArray(raw.ciStepEvidence) ||
      raw.ciStepEvidence.length !== REQUIRED_CI_STEPS.length ||
      REQUIRED_CI_STEPS.some(name =>
        raw.ciStepEvidence.filter(x => x.name === name &&
          x.passed === true).length !== 1))
    reasons.push("Required steps did not pass.");
  if (raw.result !== "DEVELOPMENT_ACCEPTANCE_AUTOMATION_PASS" ||
      raw.exactPrHeadVerified !== true ||
      raw.developmentReadyToConsiderMerge !== true)
    reasons.push("Closeout status altered.");
  for (const field of [
    "humanAcceptanceVerified",
    "operationalDeploymentApproval",
    "externalTenantsVerified",
    "externalLiveProviderVerified",
    "legalApprovalVerified",
    "backupDeletionVerified",
    "productCustomerAcceptanceVerified",
    "securityExternallyCertified",
    "sourceFixturesAreCustomerEvidence",
    "approvedGithubMerge",
    "mergedByThisWorkflow",
    "privacyOrRiskProtectionsDisabled",
  ]) if (raw[field] !== false)
    reasons.push("Unsupported approval claim: " + field);
  if (raw.githubApiWrites !== 0 ||
      !Array.isArray(raw.signaturesCollected) ||
      raw.signaturesCollected.length !== 0)
    reasons.push("Unexpected API writes or signatures.");
  if (!Array.isArray(raw.caveats) || raw.caveats.length < 6)
    reasons.push("Mandatory limitations removed.");
  return { valid: reasons.length === 0, reasons };
}
export function githubJsonClient({
  token, repositoryName, apiRoot = "https://api.github.com",
  fetchImpl = fetch,
}) {
  if (!repoSlug(repositoryName))
    throw new Error("GitHub repo name invalid.");
  if (typeof token !== "string" || token.length < 10)
    throw new Error("GitHub Actions read token absent.");
  const base = new URL(apiRoot);
  if (base.protocol !== "https:" ||
      (base.hostname !== "api.github.com" &&
       !base.hostname.endsWith(".ghe.com")))
    throw new Error("GitHub API endpoint is not trusted.");
  return async function read(path) {
    if (typeof path !== "string" || !path.startsWith("/") ||
        path.startsWith("//") || path.includes(".."))
      throw new Error("Unsafe GitHub read path.");
    const uri = new URL(path, base);
    const response = await fetchImpl(uri, {
      method: "GET",
      headers: {
        Authorization: "Bearer " + token,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok)
      throw new Error("GitHub read failed HTTP " + response.status +
        " for " + uri.pathname);
    const data = await response.json();
    if (!isRecord(data) && !Array.isArray(data))
      throw new Error("Invalid GitHub API JSON.");
    return data;
  };
}
export function createCloseoutFetcher(read, repo) {
  if (!repoSlug(repo)) throw new Error("Invalid repository.");
  if (typeof read !== "function")
    throw new Error("Missing trusted GitHub read client.");
  const route = "/repos/" + repo;
  return {
    async pr(number) {
      if (!int(number)) throw new Error("Invalid PR number.");
      return read(route + "/pulls/" + number);
    },
    async runs(commitSha) {
      if (!sha(commitSha)) throw new Error("Invalid SHA.");
      const results = [];
      for (let page = 1; page <= 3; page++) {
        const response = await read(route +
          "/actions/runs?head_sha=" + commitSha +
          "&event=pull_request&per_page=100&page=" + page);
        if (!isRecord(response) || !Array.isArray(response.workflow_runs))
          throw new Error("Invalid Actions pagination response.");
        results.push(...response.workflow_runs);
        if (response.workflow_runs.length < 100) break;
      }
      return results;
    },
    async ciJobs(runId) {
      if (!int(runId)) throw new Error("Invalid workflow run ID.");
      const result = await read(route + "/actions/runs/" + runId +
        "/jobs?per_page=100");
      if (!isRecord(result) || !Array.isArray(result.jobs))
        throw new Error("Invalid workflow job response.");
      if (result.total_count > 100)
        throw new Error("Too many CI jobs for bounded closeout.");
      return result.jobs;
    },
  };
}
export async function inspectGitHubCloseout(fetcher, options) {
  const parsed = parseCloseoutOptions(options);
  const [pr, runs] = await Promise.all([
    fetcher.pr(parsed.prNumber), fetcher.runs(parsed.commitSha),
  ]);
  const prHead = verifyPrHead(pr, parsed.commitSha, parsed.prNumber);
  if (!prHead.valid)
    throw new Error("PR identity changed or is unavailable: " +
      prHead.reasons.join("; "));
  const workflows = reconcileWorkflowRuns(runs, parsed.commitSha);
  const ci = workflows.workflows.find(x => x.name === "CI");
  let ciSteps = { valid: false, steps: [],
    reasons: ["CI has not yet completed successfully."] };
  if (ci && ci.passed)
    ciSteps = validateCiJobSteps(await fetcher.ciJobs(ci.id));
  return {
    prHead, workflows, ciSteps,
    complete: prHead.valid && workflows.valid && ciSteps.valid,
    awaiting: workflows.missing.concat(workflows.pending),
    failures: workflows.failed.concat(
      ciSteps.valid || !ci?.passed ? [] : ciSteps.reasons.map(reason =>
        ({ name: "CI_STEPS", reason }))),
  };
}
export function intervalPolicy(options) {
  const p = parseCloseoutOptions(options);
  return {
    attempts: p.maxAttempts,
    intervalMilliseconds: p.retrySeconds * 1000,
    theoreticalMaxWaitSeconds: (p.maxAttempts - 1) * p.retrySeconds,
  };
}
export async function pollCloseout(fetcher, raw, {
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
  onProgress = () => {},
} = {}) {
  const options = parseCloseoutOptions(raw);
  const policy = intervalPolicy(options);
  let last = null;
  for (let attempt = 1; attempt <= policy.attempts; attempt++) {
    last = await inspectGitHubCloseout(fetcher, options);
    onProgress({
      attempt, maxAttempts: policy.attempts,
      waitingFor: last.awaiting,
      failures: last.failures,
      complete: last.complete,
    });
    if (last.complete) return last;
    if (last.workflows.failed.length)
      throw new Error("At least one required workflow failed: " +
        JSON.stringify(last.workflows.failed));
    if (last.ciSteps.reasons.length &&
        last.workflows.workflows.find(x => x.name === "CI")?.passed)
      throw new Error("CI succeeded but required acceptance steps failed.");
    if (attempt < policy.attempts)
      await sleep(policy.intervalMilliseconds);
  }
  throw new Error("Timed out without complete identical-HEAD success: " +
    JSON.stringify({ missing: last?.workflows.missing,
      pending: last?.workflows.pending,
      ciStepFailures: last?.ciSteps.reasons }));
}
export function writeCloseoutArtifact(result, options, root = repository) {
  const parsed = parseCloseoutOptions(options);
  if (!verifyCloseoutVerdict(result).valid)
    throw new Error("Refusing to publish invalid Phase 4 closeout.");
  const absolute = resolve(root, parsed.targetPath);
  if (!absolute.startsWith(resolve(root, ".artifacts") + "/"))
    throw new Error("Closeout export escapes artifacts folder.");
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(absolute, JSON.stringify(result, null, 2) + "\n",
    { flag: "w", mode: 0o600 });
  return parsed.targetPath;
}
export async function runCloseoutCli(env = process.env) {
  const options = parseCloseoutOptions({
    repo: env.GITHUB_REPOSITORY,
    prNumber: Number(env.PHASE4_PR_NUMBER),
    commitSha: env.PHASE4_COMMIT_SHA,
    maxAttempts: Number(env.PHASE4_MAX_ATTEMPTS || 90),
    retrySeconds: Number(env.PHASE4_RETRY_SECONDS || 10),
  });
  if (env.CI !== "true" ||
      env.GITHUB_EVENT_NAME !== "pull_request")
    throw new Error("Only a pull request GitHub Actions run can attest closure.");
  const read = githubJsonClient({
    token: env.GITHUB_TOKEN,
    repositoryName: options.repo,
  });
  const fetcher = createCloseoutFetcher(read, options.repo);
  const result = await pollCloseout(fetcher, options, {
    onProgress: progress => process.stdout.write(
      "Phase4 external workflow verification: " +
      JSON.stringify(progress) + "\n"),
  });
  const manifest = createCloseoutVerdict({
    repo: options.repo, prNumber: options.prNumber,
    commitSha: options.commitSha,
    evaluatedAt: new Date().toISOString(),
    actionRunId: Number(env.GITHUB_RUN_ID),
    workflows: result.workflows,
    ciSteps: result.ciSteps,
    prHead: result.prHead,
  });
  writeCloseoutArtifact(manifest, options);
  process.stdout.write(JSON.stringify({
    result: manifest.result,
    head: manifest.commitSha, digest: manifest.digest,
    workflows: REQUIRED_WORKFLOWS.length,
    githubApiWrites: 0,
    humanApproval: false,
    mergeAuthorizedByScript: false,
  }) + "\n");
}
if (process.argv[1] && resolve(process.argv[1]) === __filename) {
  runCloseoutCli().catch(error => {
    process.stderr.write("Phase4 closeout verification FAILED: " +
      (error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  });
}
