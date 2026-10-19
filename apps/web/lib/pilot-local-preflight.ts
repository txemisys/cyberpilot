export type PilotRuntimeCheck = {
  name: string;
  ok: boolean;
  detail: string;
};

type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

type PilotRuntimeUrls = {
  appHealth: string;
  lokiReady: string;
  grafanaHealth: string;
};

const DEFAULT_URLS: PilotRuntimeUrls = {
  appHealth: "http://127.0.0.1:3000/api/health",
  lokiReady: "http://127.0.0.1:3100/ready",
  grafanaHealth: "http://127.0.0.1:3001/api/health",
};

async function fetchWithTimeout(fetcher: FetchLike, url: string) {
  return fetcher(url, {
    cache: "no-store",
    signal: AbortSignal.timeout(5_000),
  });
}

export async function checkPilotRuntime(
  fetcher: FetchLike = fetch,
  urls: Partial<PilotRuntimeUrls> = {},
): Promise<PilotRuntimeCheck[]> {
  const resolved = { ...DEFAULT_URLS, ...urls };
  const checks: PilotRuntimeCheck[] = [];

  try {
    const response = await fetchWithTimeout(fetcher, resolved.appHealth);
    const payload = response.ok
      ? ((await response.json()) as Record<string, unknown>)
      : null;
    const ok =
      response.ok &&
      payload?.status === "ok" &&
      payload?.database === "ok";

    checks.push({
      name: "CyberPilot application + PostgreSQL",
      ok,
      detail: ok
        ? "Application health is OK and PostgreSQL is reachable."
        : "Expected /api/health to report status=ok and database=ok.",
    });
  } catch {
    checks.push({
      name: "CyberPilot application + PostgreSQL",
      ok: false,
      detail:
        "CyberPilot health endpoint is unavailable. Start the app with pnpm dev:observed.",
    });
  }

  try {
    const response = await fetchWithTimeout(fetcher, resolved.lokiReady);
    checks.push({
      name: "Loki",
      ok: response.ok,
      detail: response.ok
        ? "Loki is ready."
        : "Loki readiness endpoint returned a non-success status.",
    });
  } catch {
    checks.push({
      name: "Loki",
      ok: false,
      detail:
        "Loki is unavailable. Start the local stack with pnpm dev:stack.",
    });
  }

  try {
    const response = await fetchWithTimeout(fetcher, resolved.grafanaHealth);
    checks.push({
      name: "Grafana",
      ok: response.ok,
      detail: response.ok
        ? "Grafana is reachable."
        : "Grafana health endpoint returned a non-success status.",
    });
  } catch {
    checks.push({
      name: "Grafana",
      ok: false,
      detail:
        "Grafana is unavailable. Start the local stack with pnpm dev:stack.",
    });
  }

  return checks;
}

export function assertPilotRuntimeChecks(checks: PilotRuntimeCheck[]) {
  const failures = checks.filter((check) => !check.ok);

  if (failures.length > 0) {
    throw new Error(
      failures
        .map((check) => `${check.name}: ${check.detail}`)
        .join("\n"),
    );
  }
}
