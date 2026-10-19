import { Resolver } from "node:dns/promises";

export type SpfStatus = "MISSING" | "PRESENT" | "MULTIPLE" | "ERROR";
export type DmarcStatus =
  | "MISSING"
  | "MONITORING"
  | "ENFORCING"
  | "INVALID"
  | "ERROR";
export type DkimStatus = "MISSING" | "PARTIAL" | "PUBLISHED" | "ERROR";

export type DomainSecurityObservation = {
  name: string;
  spf: {
    status: SpfStatus;
    records: string[];
  };
  dmarc: {
    status: DmarcStatus;
    policy: string | null;
    records: string[];
  };
  dkim: {
    status: DkimStatus;
    selectors: {
      selector1: string[];
      selector2: string[];
    };
  };
};

type DomainDnsResolver = {
  resolveTxt(name: string): Promise<string[][]>;
  resolveCname(name: string): Promise<string[]>;
  cancel(): void;
};

type DomainSecurityOptions = {
  resolverFactory?: () => DomainDnsResolver;
  queryTimeoutMs?: number;
};

const DNS_RESOLVER_TIMEOUT_MS = 2_000;
const DNS_RESOLVER_TRIES = 2;
const DNS_QUERY_TIMEOUT_MS = 5_000;

function createResolver(): DomainDnsResolver {
  return new Resolver({
    timeout: DNS_RESOLVER_TIMEOUT_MS,
    tries: DNS_RESOLVER_TRIES,
  });
}

function isDnsMissing(error: unknown) {
  return Boolean(
    error &&
      typeof error === "object" &&
      "code" in error &&
      ["ENODATA", "ENOTFOUND", "ENOENT", "NXDOMAIN"].includes(
        String((error as { code?: unknown }).code),
      ),
  );
}

async function runDnsQuery<T>(
  operation: (resolver: DomainDnsResolver) => Promise<T>,
  options: DomainSecurityOptions,
) {
  const resolver = (options.resolverFactory ?? createResolver)();
  const timeoutMs = options.queryTimeoutMs ?? DNS_QUERY_TIMEOUT_MS;
  let timeout: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      operation(resolver),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          resolver.cancel();

          reject(
            Object.assign(new Error("DNS query timed out."), {
              code: "ETIMEOUT",
            }),
          );
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

async function safeTxt(name: string, options: DomainSecurityOptions) {
  try {
    return {
      records: (
        await runDnsQuery((resolver) => resolver.resolveTxt(name), options)
      ).map((chunks) => chunks.join("")),
      error: false,
    };
  } catch (error) {
    if (isDnsMissing(error)) {
      return { records: [], error: false };
    }

    return { records: [], error: true };
  }
}

async function safeCname(name: string, options: DomainSecurityOptions) {
  try {
    return {
      records: await runDnsQuery(
        (resolver) => resolver.resolveCname(name),
        options,
      ),
      error: false,
    };
  } catch (error) {
    if (isDnsMissing(error)) {
      return { records: [], error: false };
    }

    return { records: [], error: true };
  }
}

export function analyzeSpfRecords(records: string[]) {
  const spfRecords = records.filter((record) =>
    record.trim().toLowerCase().startsWith("v=spf1"),
  );

  if (spfRecords.length === 0) {
    return { status: "MISSING" as const, records: [] };
  }

  if (spfRecords.length > 1) {
    return { status: "MULTIPLE" as const, records: spfRecords };
  }

  return { status: "PRESENT" as const, records: spfRecords };
}

export function analyzeDmarcRecords(records: string[]) {
  const dmarcRecords = records.filter((record) =>
    record.trim().toLowerCase().startsWith("v=dmarc1"),
  );

  if (dmarcRecords.length === 0) {
    return {
      status: "MISSING" as const,
      policy: null,
      records: [],
    };
  }

  if (dmarcRecords.length !== 1) {
    return {
      status: "INVALID" as const,
      policy: null,
      records: dmarcRecords,
    };
  }

  const tags = new Map(
    dmarcRecords[0]!
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const separator = part.indexOf("=");
        return separator === -1
          ? [part.toLowerCase(), ""]
          : [
              part.slice(0, separator).trim().toLowerCase(),
              part.slice(separator + 1).trim().toLowerCase(),
            ];
      }),
  );

  const policy = tags.get("p") ?? null;

  if (policy === "none") {
    return {
      status: "MONITORING" as const,
      policy,
      records: dmarcRecords,
    };
  }

  if (policy === "quarantine" || policy === "reject") {
    return {
      status: "ENFORCING" as const,
      policy,
      records: dmarcRecords,
    };
  }

  return {
    status: "INVALID" as const,
    policy,
    records: dmarcRecords,
  };
}

export async function observeDomainSecurity(
  domain: string,
  options: DomainSecurityOptions = {},
): Promise<DomainSecurityObservation> {
  const normalized = domain.trim().toLowerCase();

  const [rootTxt, dmarcTxt, selector1, selector2] = await Promise.all([
    safeTxt(normalized, options),
    safeTxt(`_dmarc.${normalized}`, options),
    safeCname(`selector1._domainkey.${normalized}`, options),
    safeCname(`selector2._domainkey.${normalized}`, options),
  ]);

  const spf = rootTxt.error
    ? { status: "ERROR" as const, records: [] }
    : analyzeSpfRecords(rootTxt.records);

  const dmarc = dmarcTxt.error
    ? { status: "ERROR" as const, policy: null, records: [] }
    : analyzeDmarcRecords(dmarcTxt.records);

  const dkim =
    selector1.error || selector2.error
      ? {
          status: "ERROR" as const,
          selectors: {
            selector1: selector1.records,
            selector2: selector2.records,
          },
        }
      : {
          status:
            selector1.records.length > 0 && selector2.records.length > 0
              ? ("PUBLISHED" as const)
              : selector1.records.length > 0 || selector2.records.length > 0
                ? ("PARTIAL" as const)
                : ("MISSING" as const),
          selectors: {
            selector1: selector1.records,
            selector2: selector2.records,
          },
        };

  return {
    name: normalized,
    spf,
    dmarc,
    dkim,
  };
}
