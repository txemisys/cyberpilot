# PostgreSQL backup and restore

CyberPilot treats a backup as useful only when its restore path has been exercised.

## Automated rehearsal

GitHub Actions runs a PostgreSQL logical backup/restore rehearsal on relevant pull requests, on relevant pushes to `main`, weekly, and on manual dispatch.

The rehearsal:

1. starts PostgreSQL 16;
2. applies the released Prisma migrations;
3. inserts a deterministic organization and CyberScore sentinel;
4. creates a custom-format `pg_dump`;
5. restores into a separate database;
6. verifies Prisma migration status against the restored database;
7. reads the restored sentinel through Prisma.

The workflow intentionally uses synthetic CI-only data.

A successful CI rehearsal proves that the repository's schema and logical dump/restore mechanics remain compatible. It does **not** prove that a hosting provider's managed backups, retention policy, encryption, access controls, recovery point objective, recovery time objective, or operator access are correctly configured.

## Managed staging restore gate

Before the first customer pilot, perform the same class of restore against the chosen managed PostgreSQL platform:

```text
managed staging database
→ provider backup or approved logical backup
→ separate restore target
→ migration status
→ application health
→ organization/evidence verification
```

Record:

- backup source and timestamp;
- restore target;
- operator;
- start/end timestamps;
- whether migrations were current;
- whether CyberPilot started successfully;
- whether representative organization, finding and score data were readable;
- any remediation actions required.

Do not restore a production backup into an environment with weaker access controls or broader operator access.

## Recovery ownership

Before a customer pilot, explicitly assign an owner for:

- backup policy;
- restore execution;
- restore verification;
- incident escalation;
- credential access;
- deletion of temporary restore targets.

The CI workflow is a regression control, not a substitute for operational ownership.
