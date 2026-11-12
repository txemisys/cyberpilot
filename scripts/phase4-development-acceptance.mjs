#!/usr/bin/env node
/**
 * Fail-closed, reproducible Phase 4 development acceptance.
 * This gate intentionally does NOT grant operational, legal, product,
 * provider-LIVE, backup-erasure, or customer-specific approval.
 *
 * Run from the repository root after Prisma migrations and the full CI test
 * suite have finished. CI runs this command on its checked-out commit.
 */
import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve, relative, sep } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const ACCEPTANCE_SCHEMA = "cyberpilot.phase4.development-acceptance.v1";
export const REQUIRED_SCENARIOS = Object.freeze([
  "CLEAN_REVIEW", "NO_REVIEW", "AMBIGUOUS_VERSION",
  "INCOMPLETE_SNAPSHOT", "INVALID_CHECKLIST", "MISSING_AUDIT",
  "ALTERED_FINGERPRINT", "FOREIGN_TENANT", "DUPLICATE_CASE",
  "MISSING_MAPPING", "INCOMPLETE_PROVIDER", "STALE_OBSERVATION",
  "UNRESOLVED_PROVIDER",
]);
export const REQUIRED_WORKFLOWS = Object.freeze([
  "CI", "Security", "Local stack E2E", "LAB browser journey",
  "Backup restore rehearsal",
]);
export const SOURCE_GATES = Object.freeze([
  {
    id: "CSV_IMPORT",
    criterion: "CSV import, schema and declared-source identity",
    files: [
      "apps/web/lib/assets-inventory-service.ts",
      "apps/web/lib/assets-inventory-service.integration.test.ts",
    ],
    signals: [
      { file: 0, pattern: /export async function importAssetInventory\(/ },
      { file: 1, pattern: /describe(?:\.skipIf)?\(/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "NORMALIZATION",
    criterion: "Installed software/version normalization and bounded scope",
    files: [
      "apps/web/lib/assets-inventory-service.ts",
      "apps/web/lib/assets-inventory-service.integration.test.ts",
    ],
    signals: [{ file: 1, pattern: /it\(/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "STORED_OSV",
    criterion: "Stored OSV inspection and cautious correlation",
    files: [
      "apps/web/lib/assets-osv-correlation.ts",
      "apps/web/lib/assets-osv-correlation.test.ts",
    ],
    signals: [{ file: 1, pattern: /it\(/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "SOURCE_PROVENANCE",
    criterion: "No unobserved endpoint discovery or claimed exploitability",
    files: [
      "apps/web/lib/assets-offline-acceptance-service.ts",
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
    ],
    signals: [
      { file: 1, pattern: /possibleCandidatesWithoutReview/ },
      { file: 1, pattern: /providerRequests/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "CANDIDATE_REVIEW",
    criterion: "Human case state required before considering a candidate reviewed",
    files: [
      "apps/web/lib/assets-action-case-service.ts",
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
    ],
    signals: [{ file: 1, pattern: /openAssetAdviceCase/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "ACTION_GUIDANCE",
    criterion: "Evidence-backed contextual actions",
    files: [
      "apps/web/lib/assets-action-guidance-service.ts",
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
    ],
    signals: [{ file: 1, pattern: /inspectAssetActionGuidance/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "TENANT_RBAC",
    criterion: "No cross-tenant or unauthorized read access",
    files: [
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
      "apps/web/lib/assets-offline-acceptance-run-service.integration.test.ts",
    ],
    signals: [
      { file: 0, pattern: /FORBIDDEN/ },
      { file: 0, pattern: /MISSING/ },
      { file: 1, pattern: /foreign tenant/i },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "PII_MINIMIZATION",
    criterion: "No unnecessary hostname or owner disclosure",
    files: [
      "apps/web/lib/assets-privacy-readiness-service.ts",
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
    ],
    signals: [
      { file: 1, pattern: /not\.toContain\("owner-001"\)/ },
      { file: 1, pattern: /not\.toContain\("personal-host-001"\)/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "NO_IMMEDIATE_BACKUP_ERASURE",
    criterion: "Do not claim deletions of unobserved backups",
    files: [
      "apps/web/lib/assets-privacy-readiness-service.ts",
      "apps/web/lib/assets-phase4-offline-acceptance.integration.test.ts",
    ],
    signals: [{ file: 1, pattern: /deleteBackupsImmediately/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "SCENARIO_COMPLETENESS",
    criterion: "Complete offline fixture matrix and explicit negative cases",
    files: [
      "apps/web/lib/assets-offline-scenario-matrix.ts",
      "apps/web/lib/assets-offline-scenario-matrix.test.ts",
    ],
    signals: [
      { file: 1, pattern: /SCENARIO_IDS/ },
      { file: 1, pattern: /PARTIAL_REFERENCE_SET/ },
      { file: 1, pattern: /FOREIGN_TENANT/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "AUDITED_OPERATOR_CAS",
    criterion: "Atomic operator CAS and persisted evidence references",
    files: [
      "apps/web/lib/assets-offline-acceptance-run-service.ts",
      "apps/web/lib/assets-offline-acceptance-run-service.integration.test.ts",
    ],
    signals: [
      { file: 1, pattern: /concurrent writes/ },
      { file: 1, pattern: /audit/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "INDEPENDENT_REVIEW_INTEGRITY",
    criterion: "Independent reviewer reference rules (not mandatory development signatures)",
    files: [
      "apps/web/lib/assets-evidence-independent-review.ts",
      "apps/web/lib/assets-offline-acceptance-run-service.integration.test.ts",
    ],
    signals: [{ file: 0, pattern: /export function inspectEvidenceReview/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "AUDIT_RECONCILIATION",
    criterion: "Forensic audit rejects false or incomplete CAS histories",
    files: [
      "apps/web/lib/assets-acceptance-audit-reconciliation.ts",
      "apps/web/lib/assets-acceptance-audit-reconciliation.test.ts",
    ],
    signals: [{ file: 0, pattern: /export function verifyAuditReconciliation/ }],
    owner: "DEVELOPMENT",
  },
  {
    id: "UNSIGNED_HANDOFF",
    criterion: "Local handoff export cannot claim human signatures",
    files: [
      "apps/web/lib/assets-phase4-handoff-package.ts",
      "apps/web/lib/assets-phase4-handoff-package.test.ts",
    ],
    signals: [
      { file: 0, pattern: /productAccepted: false/ },
      { file: 1, pattern: /githubMergeAuthorized/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "QUEUE_ISOLATION",
    criterion: "Bounded acceptance queue cannot approve source evidence",
    files: [
      "apps/web/lib/assets-phase4-acceptance-queue.ts",
      "apps/web/lib/assets-phase4-acceptance-queue.test.ts",
    ],
    signals: [
      { file: 0, pattern: /acceptedByProduct: false/ },
      { file: 1, pattern: /foreign-tenant/ },
    ],
    owner: "DEVELOPMENT",
  },
  {
    id: "HTTP_ACCESS_CONTROL",
    criterion: "Tenant-secured acceptance and handoff APIs",
    files: [
      "apps/web/app/api/organizations/[slug]/assets/acceptance-queue/route.ts",
      "apps/web/app/api/organizations/[slug]/assets/phase4-handoff/route.ts",
    ],
    signals: [
      { file: 0, pattern: /requireOrganizationAccess/ },
      { file: 1, pattern: /requireOrganizationAccess/ },
      { file: 0, pattern: /no-store/ },
      { file: 1, pattern: /no-store/ },
    ],
    owner: "DEVELOPMENT",
  },
]);

export const DEVELOPMENT_ONLY_POLICY = Object.freeze({
  accepts: "IMPLEMENTATION_AND_AUTOMATED_TESTS",
  operationalAcceptanceRequiredToCloseDevelopment: false,
  realCustomerDataRequired: false,
  realTenantCredentialsRequired: false,
  simulatedOperatorIdentityAcceptedAsLegalProof: false,
  evidenceGeneratedByTestsIsCustomerEvidence: false,
  externalSignaturesVerified: false,
  externalLiveProvidersVerified: false,
  backupsDeleted: false,
  legalApprovalGranted: false,
  securityCertificationGranted: false,
  operationalDeploymentApproved: false,
  productCustomerSignoffGranted: false,
  automaticMergeAuthorizedByManifest: false,
  safetyControlsRemainEnforced: true,
});

const __filename = fileURLToPath(import.meta.url);
export const REPOSITORY_ROOT = resolve(dirname(__filename), "..");

export function sha256(bufferOrString) {
  return createHash("sha256").update(bufferOrString).digest("hex");
}
export function stableCanonical(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value))
      throw new TypeError("Non-finite numbers cannot be canonicalized.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return "[" + value.map(stableCanonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  if (keys.some(key => value[key] === undefined))
    throw new TypeError("Undefined metadata cannot be canonicalized.");
  return "{" + keys.map(key =>
    JSON.stringify(key) + ":" + stableCanonical(value[key])).join(",") + "}";
}
export function digestObject(value) {
  return sha256(stableCanonical(value));
}
export function equalHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string" ||
      !/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right))
    return false;
  return timingSafeEqual(Buffer.from(left, "hex"),
    Buffer.from(right, "hex"));
}
export function safeRepoPath(root, target) {
  if (typeof target !== "string" ||
      !/^[a-zA-Z0-9_.\/[\]-]+$/.test(target) ||
      target.startsWith("/") || target.includes("\\") ||
      target.split("/").some(part => part === "." || part === ".."))
    throw new Error("Unsafe acceptance source path: " + String(target));
  const full = resolve(root, target);
  const rel = relative(resolve(root), full);
  if (rel.startsWith("..") || rel.includes(".." + sep))
    throw new Error("Acceptance source escapes repository.");
  return full;
}
export function loadSource(root, path) {
  const full = safeRepoPath(root, path);
  if (!existsSync(full)) return null;
  const bytes = readFileSync(full);
  return { bytes, content: bytes.toString("utf8"),
    digest: sha256(bytes), bytesLength: bytes.length };
}
export function inspectRequiredSources(root, catalog = SOURCE_GATES) {
  const failures = [];
  const sourceIndex = new Map();
  const criteria = [];
  const gateIds = new Set();
  for (const gate of catalog) {
    if (!gate || typeof gate.id !== "string" ||
        !/^[A-Z0-9_]{3,60}$/.test(gate.id) ||
        gateIds.has(gate.id))
      throw new Error("Invalid or duplicated development gate identifier.");
    gateIds.add(gate.id);
    const sources = [];
    for (const path of gate.files) {
      const result = sourceIndex.get(path) ?? loadSource(root, path);
      if (result) sourceIndex.set(path, result);
      sources.push({ path, found: !!result, sha256: result?.digest ?? null,
        bytes: result?.bytesLength ?? 0 });
      if (!result)
        failures.push({ gate: gate.id, reason: "MISSING_SOURCE", path });
    }
    for (const check of gate.signals) {
      const location = gate.files[check.file];
      const file = location ? sourceIndex.get(location) : null;
      if (!file || !(check.pattern instanceof RegExp) ||
          !check.pattern.test(file.content))
        failures.push({ gate: gate.id, reason: "REQUIRED_TEST_OR_GUARD_MISSING",
          path: location ?? null, signal: String(check.pattern) });
    }
    criteria.push({
      id: gate.id, criterion: gate.criterion, owner: gate.owner,
      sourceRefs: sources,
      staticGuardsDetected: gate.signals.length,
      status: failures.some(f => f.gate === gate.id) ? "FAIL" : "PASS_STATIC",
    });
  }
  return {
    criteria, failures,
    sourceCount: sourceIndex.size,
    sources: [...sourceIndex.entries()].map(([path, source]) =>
      ({ path, sha256: source.digest, bytes: source.bytesLength }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    complete: failures.length === 0 && criteria.length === catalog.length,
  };
}
export function runScenarioContract(root) {
  const location = "apps/web/lib/assets-offline-scenario-matrix.ts";
  const source = loadSource(root, location);
  if (!source) return { valid: false, source: location, observed: [],
    missing: [...REQUIRED_SCENARIOS],
    reason: "Missing synthetic scenario matrix implementation." };
  const observed = REQUIRED_SCENARIOS.filter(key =>
    new RegExp('["\\\x27]' + key + '["\\\x27]').test(source.content));
  const missing = REQUIRED_SCENARIOS.filter(key => !observed.includes(key));
  return {
    valid: missing.length === 0,
    source: location, sha256: source.digest,
    observed, missing,
    executedByThisStaticCheck: false,
    executedByRequiredVitestSuite: true,
    referenceFixturesAreCustomerApproval: false,
    explanation: "Static scenario presence; actual behavior is validated by mandatory Vitest in CI.",
  };
}
export function validateCiEvidence(input) {
  if (!input || typeof input !== "object")
    return { valid: false, issues: ["Missing exact-commit CI evidence."] };
  const issues = [];
  if (!/^[a-f0-9]{40}$/.test(input.commitSha ?? ""))
    issues.push("No exact 40-character Git commit SHA.");
  if (input.workflowName !== "CI")
    issues.push("Development gate must run within the CI workflow.");
  if (input.testResult !== "SUCCESS" ||
      input.typecheckResult !== "SUCCESS" ||
      input.migrationsResult !== "SUCCESS")
    issues.push("Mandatory CI suite, typecheck, or migration failed.");
  if (input.buildResult === "SUCCESS" && input.buildExecutedAfterGate)
    issues.push("A later build cannot be pre-attested inside an earlier gate.");
  return { valid: issues.length === 0, issues };
}
export function createDevelopmentManifest({
  commitSha, source, scenario, recordedAt, ciEvidence,
}) {
  if (!source?.complete || !scenario?.valid)
    throw new Error("Cannot attest incomplete development acceptance.");
  if (!/^[a-f0-9]{40}$/.test(commitSha))
    throw new Error("Exact Git commit is required for acceptance.");
  if (!Number.isFinite(Date.parse(recordedAt)))
    throw new Error("Manifest evaluation timestamp invalid.");
  const ci = validateCiEvidence(ciEvidence);
  if (!ci.valid || ciEvidence.commitSha !== commitSha)
    throw new Error("CI evidence does not match exact manifest HEAD.");
  const base = {
    schema: ACCEPTANCE_SCHEMA,
    commitSha,
    evaluatedAt: recordedAt,
    scope: "PHASE_4_OFFLINE_DEVELOPMENT_ONLY",
    issue: "https://github.com/txemisys/cyberpilot/issues/86",
    criteria: source.criteria,
    manifestSourceFiles: source.sources,
    staticSourceChecks: source.criteria.length,
    sourceReadiness: "PASS_STATIC",
    syntheticScenarios: {
      ...scenario, referenceFixturesAreCustomerApproval: false,
    },
    prerequisites: {
      migrations: "SUCCESS_VERIFIED_IN_CI_STEP",
      typecheck: "SUCCESS_VERIFIED_IN_CI_STEP",
      fullTestSuite: "SUCCESS_VERIFIED_IN_CI_STEP",
      build: "PENDING_CI_BUILD_STEP",
      security: "CHECK_SEPARATELY_ON_SAME_HEAD",
      stackE2E: "CHECK_SEPARATELY_ON_SAME_HEAD",
      labBrowser: "CHECK_SEPARATELY_ON_SAME_HEAD",
      backupRestore: "CHECK_SEPARATELY_ON_SAME_HEAD",
    },
    excludedProviderLive: true,
    excludesCustomerOperationalAcceptance: true,
    assertionsFromThisGate: "SOURCE_CONTRACT_AND_POST_TEST_CI",
    policy: DEVELOPMENT_ONLY_POLICY,
    githubMergeAuthorized: false,
    productOrLegalApprovalGranted: false,
    controlsChangedByThisEvaluation: false,
    databaseWrites: 0,
    externalProviderRequests: 0,
    reviewerSignatures: [],
    informationalLimitations: [
      "A green gate is a development signal, not certification or legal advice.",
      "The remaining four workflows must be checked independently on the same exact HEAD.",
      "The build occurs after this gate and must independently pass in CI.",
      "Static guard presence is weaker than behavioral tests; mandatory CI tests execute those behaviors.",
      "No real tenant, live provider, customer evidence or responsible human signature is asserted.",
      "The manifest is unsigned; a local SHA-256 is not an externally authenticated signature.",
      "Merge additionally depends on GitHub protection rules and the authorized maintainer.",
    ],
  };
  return { ...base, digest: digestObject(base) };
}
export function verifyDevelopmentManifest(manifest) {
  if (!manifest || typeof manifest !== "object") return {
    valid: false, issues: ["Manifest missing."],
  };
  const { digest, ...canonical } = manifest;
  const issues = [];
  if (!equalHex(digest, digestObject(canonical)))
    issues.push("Manifest digest mismatch.");
  if (manifest.schema !== ACCEPTANCE_SCHEMA ||
      !/^[a-f0-9]{40}$/.test(manifest.commitSha ?? ""))
    issues.push("Manifest identity invalid.");
  if (manifest.githubMergeAuthorized || manifest.productOrLegalApprovalGranted ||
      manifest.controlsChangedByThisEvaluation || manifest.databaseWrites !== 0 ||
      manifest.externalProviderRequests !== 0)
    issues.push("Manifest contains unsupported actions or approvals.");
  if (manifest.policy?.operationalAcceptanceRequiredToCloseDevelopment !== false ||
      manifest.policy?.safetyControlsRemainEnforced !== true ||
      manifest.policy?.externalSignaturesVerified !== false ||
      manifest.policy?.realTenantCredentialsRequired !== false)
    issues.push("Development and operations boundaries changed.");
  if (!manifest.excludedProviderLive ||
      !manifest.excludesCustomerOperationalAcceptance ||
      manifest.syntheticScenarios?.referenceFixturesAreCustomerApproval)
    issues.push("Synthetic and LIVE scope must remain explicit.");
  if (manifest.criteria?.length !== SOURCE_GATES.length ||
      manifest.criteria?.some(g => g.status !== "PASS_STATIC"))
    issues.push("Not every development criterion passed.");
  return { valid: issues.length === 0, issues };
}
export function resolveGitHead(root, env = process.env) {
  const reported = env.PHASE4_COMMIT_SHA || env.GITHUB_SHA;
  if (reported) {
    if (!/^[a-f0-9]{40}$/.test(reported))
      throw new Error("Invalid CI commit SHA.");
    return reported;
  }
  try {
    const sha = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root, encoding: "utf8", timeout: 10000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (/^[a-f0-9]{40}$/.test(sha)) return sha;
  } catch { /* the next message is the actionable error */ }
  throw new Error("A verifiable exact commit SHA is required.");
}
export function validateGateInvocation(env = process.env) {
  const issues = [];
  if (env.CI !== "true") issues.push("CI=true is mandatory.");
  if (env.GITHUB_WORKFLOW !== "CI")
    issues.push("GitHub workflow must be CI.");
  if (env.PHASE4_CI_TESTS_PASSED !== "true")
    issues.push("Full test suite must pass before gate.");
  if (env.PHASE4_CI_TYPECHECK_PASSED !== "true")
    issues.push("Typecheck must pass before gate.");
  if (env.PHASE4_CI_MIGRATIONS_PASSED !== "true")
    issues.push("Prisma migration status must pass before gate.");
  if (env.PHASE4_CI_SKIP_GATES === "true" ||
      env.PHASE4_ACCEPT_WITHOUT_TESTS === "true")
    issues.push("Acceptance bypass variables are prohibited.");
  return { valid: issues.length === 0, issues };
}
export function runDevelopmentGate({
  root = REPOSITORY_ROOT, env = process.env, clock = new Date(),
} = {}) {
  const invocation = validateGateInvocation(env);
  if (!invocation.valid)
    throw new Error("Invalid CI invocation: " + invocation.issues.join("; "));
  const commitSha = resolveGitHead(root, env);
  const source = inspectRequiredSources(root);
  const scenario = runScenarioContract(root);
  if (!source.complete || !scenario.valid)
    throw new Error("Phase 4 source contract failed: " +
      JSON.stringify({ sourceFailures: source.failures,
        missingScenarios: scenario.missing }));
  const manifest = createDevelopmentManifest({
    commitSha, source, scenario,
    recordedAt: clock.toISOString(),
    ciEvidence: {
      commitSha, workflowName: env.GITHUB_WORKFLOW,
      testResult: "SUCCESS", typecheckResult: "SUCCESS",
      migrationsResult: "SUCCESS",
      buildResult: "PENDING", buildExecutedAfterGate: false,
    },
  });
  const verified = verifyDevelopmentManifest(manifest);
  if (!verified.valid)
    throw new Error("Generated manifest could not be verified: " +
      verified.issues.join("; "));
  const target = env.PHASE4_ATTESTATION_PATH ||
    ".artifacts/phase4-development-acceptance.json";
  const output = safeRepoPath(root, target);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, JSON.stringify(manifest, null, 2) + "\n",
    { encoding: "utf8", mode: 0o600, flag: "w" });
  return {
    output: target, digest: manifest.digest,
    gates: manifest.criteria.length, scenarios: scenario.observed.length,
    commitSha,
    verdict: "TECHNICAL_DEVELOPMENT_GATE_PASS_PENDING_FINAL_WORKFLOWS",
    humanAcceptance: "NOT_REQUIRED_FOR_DEVELOPMENT",
    deploymentApproval: "NOT_GRANTED",
  };
}
export function runCli() {
  try {
    const result = runDevelopmentGate();
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } catch (error) {
    process.stderr.write("Phase 4 development gate FAILED: " +
      (error instanceof Error ? error.message : String(error)) + "\n");
    process.exitCode = 1;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === __filename)
  runCli();
