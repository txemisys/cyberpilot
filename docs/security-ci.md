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

## Reproducible dependency installs

The repository commits `pnpm-lock.yaml` and pins the package manager through:

```text
pnpm@9.15.4
```

Normal CI installs dependencies with:

```text
pnpm install --frozen-lockfile
```

This makes dependency resolution deterministic for a given repository revision and causes CI to fail when a package manifest changes without the corresponding lockfile update.

This closes the previous reproducibility gap. It does not by itself complete supply-chain hardening: Dependency Review still depends on the repository-level Dependency Graph setting described above.

## Secret scanning

Do not add third-party secret-scanning actions merely to create another badge.

For a public GitHub repository, prefer GitHub's repository-native secret-scanning capabilities where available, plus prevention at the secret-manager/deployment boundary.

No workflow should print production environment values or provider credentials.
