import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync,
  readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  ACCEPTANCE_SCHEMA, REQUIRED_SCENARIOS, REQUIRED_WORKFLOWS,
  SOURCE_GATES, DEVELOPMENT_ONLY_POLICY, REPOSITORY_ROOT,
  sha256, stableCanonical, digestObject, equalHex, safeRepoPath,
  loadSource, inspectRequiredSources, runScenarioContract,
  validateCiEvidence, createDevelopmentManifest,
  verifyDevelopmentManifest, resolveGitHead, validateGateInvocation,
  runDevelopmentGate,
} from "./phase4-development-acceptance.mjs";

const head = "a".repeat(40);
const now = "2026-11-12T10:00:00.000Z";
const ci = {
  CI: "true",
  GITHUB_WORKFLOW: "CI",
  GITHUB_SHA: head,
  PHASE4_COMMIT_SHA: head,
  PHASE4_CI_TESTS_PASSED: "true",
  PHASE4_CI_TYPECHECK_PASSED: "true",
  PHASE4_CI_MIGRATIONS_PASSED: "true",
};
const ciEvidence = {
  commitSha: head, workflowName: "CI",
  testResult: "SUCCESS", typecheckResult: "SUCCESS",
  migrationsResult: "SUCCESS", buildResult: "PENDING",
  buildExecutedAfterGate: false,
};
function fixture(fn) {
  const path = mkdtempSync(join(tmpdir(), "phase4-development-gate-"));
  try { return fn(path); } finally {
    rmSync(path, { recursive: true, force: true });
  }
}
function write(path, name, value) {
  const full = safeRepoPath(path, name);
  mkdirSync(dirname(full), { recursive: true });
  writeFileSync(full, value);
}
function fakeCatalog() {
  return [
    { id: "FIRST", criterion: "real source", owner: "DEVELOPMENT",
      files: ["src/source.ts", "src/check.test.ts"],
      signals: [
        { file: 0, pattern: /sourceReady/ },
        { file: 1, pattern: /should reject invalid input/ },
      ] },
    { id: "SECOND", criterion: "second signal", owner: "DEVELOPMENT",
      files: ["src/second.ts"],
      signals: [{ file: 0, pattern: /tenantGuard/ }] },
  ];
}
function validSources() {
  return {
    complete: true, criteria: SOURCE_GATES.map(g => ({
      id: g.id, criterion: g.criterion, owner: g.owner,
      sourceRefs: [], staticGuardsDetected: g.signals.length,
      status: "PASS_STATIC",
    })),
    sources: [{ path: "lib/source.ts", sha256: "b".repeat(64),
      bytes: 100 }],
  };
}
function validScenarios() {
  return {
    valid: true, source: "apps/web/lib/assets-offline-scenario-matrix.ts",
    sha256: "b".repeat(64), observed: [...REQUIRED_SCENARIOS],
    missing: [], executedByThisStaticCheck: false,
    executedByRequiredVitestSuite: true,
    referenceFixturesAreCustomerApproval: false,
  };
}
function manifest() {
  return createDevelopmentManifest({
    commitSha: head, source: validSources(),
    scenario: validScenarios(), recordedAt: now, ciEvidence,
  });
}

test("Phase 4 gate exposes all mandatory criteria, scenarios and workflows", () => {
  assert.equal(ACCEPTANCE_SCHEMA,
    "cyberpilot.phase4.development-acceptance.v1");
  assert.equal(SOURCE_GATES.length, 16);
  assert.equal(REQUIRED_SCENARIOS.length, 13);
  assert.equal(new Set(REQUIRED_SCENARIOS).size, 13);
  assert.equal(new Set(SOURCE_GATES.map(x => x.id)).size, 16);
  assert.equal(new Set(REQUIRED_WORKFLOWS).size, 5);
  assert.deepEqual(REQUIRED_WORKFLOWS, [
    "CI", "Security", "Local stack E2E", "LAB browser journey",
    "Backup restore rehearsal",
  ]);
});
test("No human signoff or customer LIVE proof is implied by developer tests", () => {
  assert.equal(DEVELOPMENT_ONLY_POLICY.operationalAcceptanceRequiredToCloseDevelopment,
    false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.externalSignaturesVerified, false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.legalApprovalGranted, false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.backupsDeleted, false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.externalLiveProvidersVerified, false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.automaticMergeAuthorizedByManifest,
    false);
  assert.equal(DEVELOPMENT_ONLY_POLICY.safetyControlsRemainEnforced, true);
});
test("Canonical JSON hash is independent of insertion key order", () => {
  assert.equal(stableCanonical({ x: 1, y: 2 }),
    stableCanonical({ y: 2, x: 1 }));
  assert.equal(digestObject({ x: { c: true, a: null } }),
    digestObject({ x: { a: null, c: true } }));
  assert.equal(sha256("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(equalHex("a".repeat(64), "a".repeat(64)), true);
  assert.equal(equalHex("a".repeat(64), "b".repeat(64)), false);
  assert.equal(equalHex("A".repeat(64), "a".repeat(64)), false);
  assert.equal(equalHex("invalid", "invalid"), false);
  assert.throws(() => stableCanonical({ missing: undefined }));
  assert.throws(() => stableCanonical({ bad: Infinity }));
});
test("Path validator rejects traversal, absolute paths and arbitrary names", () => {
  fixture(root => {
    for (const bad of [
      "../outside", "src/../../outside", "/tmp/outside",
      "src\\outside", "src/./inner", "src/../inner",
      "src/sub;rm -rf .", "", ".", "..",
    ]) assert.throws(() => safeRepoPath(root, bad));
    assert.equal(safeRepoPath(root, "apps/web/lib/example.ts"),
      join(root, "apps/web/lib/example.ts"));
    assert.equal(safeRepoPath(root,
      "apps/web/app/api/organizations/[slug]/assets/route.ts"),
      join(root, "apps/web/app/api/organizations/[slug]/assets/route.ts"));
  });
});
test("Source inspection identifies missing files rather than silently passing", () => {
  fixture(root => {
    const result = inspectRequiredSources(root, fakeCatalog());
    assert.equal(result.complete, false);
    assert.equal(result.criteria.filter(x => x.status === "FAIL").length, 2);
    assert.equal(result.failures.some(x => x.reason === "MISSING_SOURCE"),
      true);
  });
});
test("Source inspection fingerprints every file and checks required guards", () => {
  fixture(root => {
    write(root, "src/source.ts", "const sourceReady = true;");
    write(root, "src/check.test.ts",
      'it("should reject invalid input", () => {});');
    write(root, "src/second.ts", "const tenantGuard = true;");
    const result = inspectRequiredSources(root, fakeCatalog());
    assert.equal(result.complete, true);
    assert.equal(result.sourceCount, 3);
    assert.equal(result.criteria.length, 2);
    assert.equal(result.criteria.every(x => x.status === "PASS_STATIC"), true);
    assert.equal(result.sources.find(x =>
      x.path === "src/source.ts")?.sha256,
    sha256("const sourceReady = true;"));
  });
});
test("Gate fails closed when a required regression assertion disappears", () => {
  fixture(root => {
    write(root, "src/source.ts", "const sourceReady = true;");
    write(root, "src/check.test.ts", 'it("wrong test", () => {});');
    write(root, "src/second.ts", "const tenantGuard = true;");
    const result = inspectRequiredSources(root, fakeCatalog());
    assert.equal(result.complete, false);
    assert.deepEqual(result.failures.map(x => x.reason),
      ["REQUIRED_TEST_OR_GUARD_MISSING"]);
  });
});
test("Duplicate catalog gate identifiers are rejected", () => {
  fixture(root => {
    assert.throws(() => inspectRequiredSources(root, [
      fakeCatalog()[0], fakeCatalog()[0],
    ]), /duplicated/);
  });
});
test("Scenario contract requires all thirteen known negative and positive cases", () => {
  const real = runScenarioContract(REPOSITORY_ROOT);
  assert.equal(real.valid, true, JSON.stringify(real.missing));
  assert.deepEqual(real.missing, []);
  assert.deepEqual(real.observed, [...REQUIRED_SCENARIOS]);
  assert.equal(real.executedByThisStaticCheck, false);
  assert.equal(real.executedByRequiredVitestSuite, true);
});
test("Scenario inspection refuses missing or incomplete fixture catalogs", () => {
  fixture(root => {
    let check = runScenarioContract(root);
    assert.equal(check.valid, false);
    assert.equal(check.missing.length, 13);
    write(root, "apps/web/lib/assets-offline-scenario-matrix.ts",
      'export const SCENARIO_IDS = ["CLEAN_REVIEW", "NO_REVIEW"];');
    check = runScenarioContract(root);
    assert.equal(check.valid, false);
    assert.equal(check.observed.length, 2);
    assert.equal(check.missing.length, 11);
  });
});
test("Actual repository must contain all 16 developer safety contracts", () => {
  const inspection = inspectRequiredSources(REPOSITORY_ROOT);
  assert.equal(inspection.complete, true,
    JSON.stringify(inspection.failures));
  assert.equal(inspection.criteria.length, SOURCE_GATES.length);
  assert.ok(inspection.sources.length >= 16);
});
test("Workflow evidence cannot lie about a nonexistent test run", () => {
  assert.equal(validateCiEvidence(ciEvidence).valid, true);
  for (const modification of [
    { testResult: "PENDING" }, { typecheckResult: "FAILURE" },
    { migrationsResult: "SKIPPED" }, { workflowName: "Security" },
    { commitSha: "invalid" },
    { buildResult: "SUCCESS", buildExecutedAfterGate: true },
  ]) assert.equal(validateCiEvidence({
    ...ciEvidence, ...modification,
  }).valid, false);
});
test("Exact-commit CI environment is required and cannot be bypassed", () => {
  assert.equal(validateGateInvocation(ci).valid, true);
  for (const modification of [
    { CI: "false" }, { GITHUB_WORKFLOW: "Security" },
    { PHASE4_CI_TESTS_PASSED: "false" },
    { PHASE4_CI_TYPECHECK_PASSED: "false" },
    { PHASE4_CI_MIGRATIONS_PASSED: "false" },
    { PHASE4_CI_SKIP_GATES: "true" },
    { PHASE4_ACCEPT_WITHOUT_TESTS: "true" },
  ]) assert.equal(validateGateInvocation({
    ...ci, ...modification,
  }).valid, false);
});
test("Pull request exact HEAD takes precedence over workflow merge SHA", () => {
  assert.equal(resolveGitHead(REPOSITORY_ROOT, {
    GITHUB_SHA: "b".repeat(40),
    PHASE4_COMMIT_SHA: head,
  }), head);
  assert.throws(() => resolveGitHead(REPOSITORY_ROOT, {
    PHASE4_COMMIT_SHA: "invalid",
  }));
});
test("Manifest requires source contract and matching test commit", () => {
  const source = validSources();
  assert.throws(() => createDevelopmentManifest({
    commitSha: head, source: { ...source, complete: false },
    scenario: validScenarios(), recordedAt: now, ciEvidence,
  }));
  assert.throws(() => createDevelopmentManifest({
    commitSha: head, source, scenario: { ...validScenarios(), valid: false },
    recordedAt: now, ciEvidence,
  }));
  assert.throws(() => createDevelopmentManifest({
    commitSha: "bad", source, scenario: validScenarios(),
    recordedAt: now, ciEvidence,
  }));
  assert.throws(() => createDevelopmentManifest({
    commitSha: "b".repeat(40), source, scenario: validScenarios(),
    recordedAt: now, ciEvidence,
  }));
});
test("Unsigned development manifest cannot grant product merge or LIVE", () => {
  const result = manifest();
  assert.equal(result.schema, ACCEPTANCE_SCHEMA);
  assert.equal(result.githubMergeAuthorized, false);
  assert.equal(result.productOrLegalApprovalGranted, false);
  assert.equal(result.externalProviderRequests, 0);
  assert.equal(result.databaseWrites, 0);
  assert.equal(result.policy.operationalAcceptanceRequiredToCloseDevelopment,
    false);
  assert.equal(result.policy.safetyControlsRemainEnforced, true);
  assert.equal(result.prerequisites.build, "PENDING_CI_BUILD_STEP");
  assert.equal(result.prerequisites.security,
    "CHECK_SEPARATELY_ON_SAME_HEAD");
  assert.equal(verifyDevelopmentManifest(result).valid, true);
});
test("Digest verifies independently and rejects mutation", () => {
  const result = manifest();
  assert.equal(equalHex(result.digest, digestObject(
    Object.fromEntries(Object.entries(result).filter(([k]) =>
      k !== "digest")))), true);
  result.criteria[0].status = "FAIL";
  assert.equal(verifyDevelopmentManifest(result).valid, false);
});
test("Even a recomputed digest cannot forge a false external signature", () => {
  const result = manifest();
  result.productOrLegalApprovalGranted = true;
  const { digest, ...canonical } = result;
  result.digest = digestObject(canonical);
  assert.equal(verifyDevelopmentManifest(result).valid, false);
});
test("Gate refuses missing CI markers before reading repository files", () => {
  fixture(root => assert.throws(() => runDevelopmentGate({
    root, env: { ...ci, PHASE4_CI_TESTS_PASSED: "false" },
    clock: new Date(now),
  }), /Invalid CI invocation/));
});
test("Full gate writes a local manifest bound to the exact HEAD", () => {
  fixture(root => {
    // Source checks always use the caller-provided root: a different
    // repository cannot be silently substituted for the checked-out one.
    assert.throws(() => runDevelopmentGate({
      root, env: { ...ci, PHASE4_ATTESTATION_PATH:
        ".artifacts/development.json" },
      clock: new Date(now),
    }), /source contract failed/);
    assert.equal(existsSync(join(root, ".artifacts/development.json")),
      false);
  });
});
test("Manifest preserves a complete issue 86 acceptance trace", () => {
  const result = manifest();
  assert.equal(result.issue,
    "https://github.com/txemisys/cyberpilot/issues/86");
  assert.equal(result.criteria.length, 16);
  assert.equal(new Set(result.criteria.map(x => x.id)).size, 16);
  assert.equal(result.syntheticScenarios.observed.length, 13);
  assert.equal(result.syntheticScenarios.missing.length, 0);
  assert.equal(result.reviewerSignatures.length, 0);
  assert.equal(result.informationalLimitations.length >= 6, true);
});
