# Local-first development

CyberPilot must be developable and integration-testable without a paid hosting, logging or database service.

The default development architecture is:

```text
browser / Microsoft Entra
        |
        | HTTPS only when a public callback is required
        v
Tailscale Funnel (optional)
        |
        v
Next.js on localhost:3000
        |
        +--> PostgreSQL 16 (Docker)
        |
        +--> structured JSON log file
                 |
                 v
              Alloy --> Loki --> Grafana
```

Tailscale Funnel is required only when a public HTTPS callback is needed, such as Microsoft OAuth. Normal Lab development remains localhost-only.

## Prerequisites

- Node.js 22.12+
- pnpm 9.15.4 through Corepack
- Docker with Compose v2
- optional: Tailscale CLI for public HTTPS integration testing

No Render, Datadog, hosted PostgreSQL or other paid infrastructure is required for the development loop.

## Start local infrastructure

```bash
pnpm dev:stack
```

This starts PostgreSQL 16 on `localhost:5432`, Loki on `localhost:3100`, Grafana on `http://localhost:3001`, and Grafana Alloy for local log collection.

Apply migrations:

```bash
pnpm db:migrate:deploy
pnpm db:migrate:status
```

## Start CyberPilot with local log collection

```bash
pnpm dev:observed
```

This runs the normal Next.js development server and mirrors stdout/stderr to:

```text
var/log/cyberpilot/app.log
```

Alloy tails that file into Loki. Grafana is pre-provisioned with Loki as the default datasource.

## Microsoft OAuth over public HTTPS

For a LIVE read-only development tenant, expose localhost port 3000 with:

```bash
pnpm dev:funnel
```

The Tailscale CLI prints the public `https://...ts.net` URL. Set:

```text
BETTER_AUTH_URL=https://<device>.<tailnet>.ts.net
M365_GRAPH_REDIRECT_URI=https://<device>.<tailnet>.ts.net/api/integrations/microsoft-365/callback
```

Configure the same callback URI in the development Microsoft Entra app registration.

The first LIVE tenant remains read-only. Keep every `M365_REMEDIATION_*` value empty.

Stop/reset Funnel with:

```bash
pnpm dev:funnel:stop
```

Funnel is an optional development ingress mechanism, not a production hosting dependency.

## Local backup and restore

Create a logical backup:

```bash
pnpm dev:backup
```

Backups are written under `backups/`, which is gitignored.

Restore into an isolated local database:

```bash
pnpm dev:restore -- backups/<file>.dump
```

The restore target is `cyberpilot_restore`, leaving the normal development database untouched.

## Stop or reset

Stop containers while keeping volumes:

```bash
pnpm dev:stack:down
```

Delete local PostgreSQL/Loki/Grafana volumes:

```bash
pnpm dev:stack:reset
```

The reset command destroys local development data only.

## Development acceptance

The zero-cost development path is healthy when:

1. PostgreSQL starts locally;
2. migrations apply;
3. CyberPilot starts with `pnpm dev:observed`;
4. `GET /api/health` is healthy;
5. structured events are queryable in Grafana/Loki;
6. backup and isolated restore work;
7. when Microsoft integration is tested, Funnel provides the HTTPS callback during the test session;
8. scanner permissions remain limited to the documented read-only set.

A paid managed service can later improve availability, retention and operational ownership, but must not be required to implement or test application functionality.
