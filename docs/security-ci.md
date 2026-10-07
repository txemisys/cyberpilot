# Security CI baseline

CyberPilot uses a separate GitHub Actions security workflow in addition to the normal build/test workflow.

## Dependency Review

On pull requests, GitHub Dependency Review checks dependency changes and fails when a newly introduced dependency has a known **high** or **critical** severity vulnerability.

This is an admission control for new dependency changes, not a complete inventory of every historical package risk.

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
