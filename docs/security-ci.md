# Security CI baseline

CyberPilot uses a separate GitHub Actions security workflow in addition to the normal build/test workflow.

The current executable control is CodeQL. Dependency Review is prepared but blocked on the repository Dependency Graph setting.

## Dependency Review — repository setting required

The dependency-review action was exercised during implementation and GitHub rejected it because Dependency Graph is currently disabled for this repository.

Enable it in:

```text
Repository Settings
→ Advanced Security / Security and quality
→ Dependency Graph / Dependabot alerts
```

After that setting is enabled, add `actions/dependency-review-action@v4` back to this workflow and fail pull requests on newly introduced high/critical vulnerable dependencies.

Do not keep a permanently failing workflow while the repository-level prerequisite is disabled.

## CodeQL

CodeQL analyzes JavaScript / TypeScript on:

- pull requests;
- pushes to `main`;
- a weekly scheduled run.

Results are uploaded to GitHub code scanning.

## Important current limitation: no committed pnpm lockfile

The repository still does not commit `pnpm-lock.yaml`.

That limits:

- reproducible installs;
- exact transitive dependency review;
- deterministic build provenance;
- confidence in dependency-diff analysis.

Creating and committing a lockfile is a priority follow-up. CI should then switch from:

```text
pnpm install --no-frozen-lockfile
```

to:

```text
pnpm install --frozen-lockfile
```

Do not describe supply-chain hardening as complete until that is done.

## Secret scanning

Do not add third-party secret-scanning actions merely to create another badge.

For a public GitHub repository, prefer GitHub's repository-native secret-scanning capabilities where available, plus prevention at the secret-manager/deployment boundary.

No workflow should print production environment values or provider credentials.
