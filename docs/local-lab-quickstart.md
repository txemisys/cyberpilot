# Local Lab quickstart

This guide runs CyberPilot locally without a Microsoft 365 tenant.

## Prerequisites

- Node.js 22.12 or newer
- Corepack
- Docker Desktop or another local PostgreSQL 16 instance

## 1. Start PostgreSQL

Using Docker:

```bash
docker run --name cyberpilot-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyberpilot \
  -p 5432:5432 \
  -d postgres:16
```

If the container already exists:

```bash
docker start cyberpilot-postgres
```

## 2. Configure the app

Copy the example environment file to the web application:

```bash
cp .env.example apps/web/.env.local
```

Set at least:

```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cyberpilot"
AUTH_SECRET="<generate-a-local-secret>"
BETTER_AUTH_URL="http://localhost:3000"
LAB_AUTH_ENABLED="true"
```

Microsoft client IDs and secrets can remain empty for Lab Mode.

Generate a local auth secret with:

```bash
openssl rand -base64 32
```

## 3. Install dependencies

```bash
corepack enable
pnpm install
```

The repository pins pnpm 9.15.4 through the root `packageManager` field.

## 4. Prepare the database

For a fresh local database:

```bash
pnpm db:generate
pnpm db:migrate:deploy
```

If the database was created before the migration baseline existed and already matches the current Prisma schema, mark the baseline as applied once:

```bash
pnpm db:migrate:baseline
pnpm db:migrate:status
```

For future schema development, create versioned migrations with:

```bash
pnpm db:migrate:dev
```

`db:push` remains available only as a local-development escape hatch and must not be used for staging or production deployment.

## 5. Start CyberPilot

```bash
pnpm dev
```

Open:

```text
http://localhost:3000/login
```

When `LAB_AUTH_ENABLED=true` and the application is running in development, the login page shows **Local Lab access**.

Create a local account with any development-only email and a password of at least eight characters.

Then:

1. create an organization;
2. open the organization;
3. choose **Start Microsoft 365 Lab**;
4. review the generated findings and CyberScore;
5. approve the guest Global Administrator remediation;
6. execute the approved remediation;
7. verify the finding resolves and posture history changes.

## Safety

Local Lab authentication is ignored when `NODE_ENV=production`.

Microsoft 365 Lab Mode does not call Microsoft Graph or modify a real tenant.

Do not reuse local development passwords or secrets for real accounts.


## Recover a Local Lab password

Local Lab password recovery is development-only and does not send real email.

1. On the login page, enter the Local Lab account email and choose **Forgot password?**
2. CyberPilot prints a one-time reset URL in the terminal running `pnpm dev`.
3. Open that URL and choose a new password.
4. The reset token expires after 10 minutes and existing sessions are revoked.

Never expose or copy the reset URL into shared logs. Production deployments must use a real delivery channel rather than the Local Lab terminal flow.
