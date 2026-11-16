import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { request as httpsRequest } from "node:https";
import { isPublicExposureAddress,
  type PassiveExecutionTransport,
} from "@cyberpilot/risk-engine";

/**
 * Node-side passive socket adapter. No default instance, no PUBLIC
 * route and no automatic startup: constructing it demands an
 * independently enabled operator gate and a live feature flag.
 *
 * Safety properties:
 * - One exact canonical domain; port 443 only; never arbitrary URLs.
 * - DNS queries only for the authorized name and its _dmarc TXT.
 * - Public addresses only and caller-supplied DNS/IP socket pinning.
 * - HEAD cannot include credentials, cookies, body or redirects.
 * - Peer IP is read from the actual socket, not supplied externally.
 * - Every DNS query and socket operation invokes an async authorization
 *   callback which must reserve quota BEFORE execution.
 */
export type IsolatedNetworkAction =
  "DNS_A" | "DNS_AAAA" | "DNS_TXT" | "DNS_MX" |
  "TLS_CONNECT" | "HTTPS_HEAD";
export type IsolatedNetworkScope = {
  organizationId: string;
  requestId: string;
  domain: string;
  authorizationId: string;
  authorizationRevision: number;
  grantId: string;
  consentDigest: string;
  leaseId: string;
  leaseExpiresAt: string;
  maximumOperations: number;
  executableByIndependentAuthority: true;
};
export type IsolatedNetworkOperator = {
  schema: "cyberpilot.exposure.network.operator.v1";
  liveFeatureEnabled: true;
  operatorId: string;
  independentlyApprovedWorker: true;
  isolatedExecutionEnvironment: true;
  trustedQuotaAdapterPresent: true;
  scopedExecutionLeasePresent: true;
};
export type IsolatedNetworkAuthorization = {
  /**
   * Operator-provided backend must check atomic quotas, revocation
   * and authorization revisions for every actual network operation.
   * This module cannot decide legal consent from the browser.
   */
  authorizeNetworkAction(
    scope: IsolatedNetworkScope, action: IsolatedNetworkAction,
    hostname: string, pinnedIp: string | null,
  ): Promise<boolean>;
  independentlyOperated: true;
};
export type IsolatedNetworkMetrics = {
  schema: "cyberpilot.exposure.network.metrics.v1";
  requestId: string; organizationId: string; domain: string;
  dnsA: number; dnsAAAA: number; dnsTXT: number; dnsMX: number;
  tlsHandshakes: number; headRequests: number;
  totalAttempted: number; totalAuthorized: number;
  denied: number; protocolErrors: number;
  bytesAccepted: number;
  lastErrorCode: string | null;
  passwordOrCookieSent: false;
  httpResponseBodyCollected: false;
  redirectedRequestsFollowed: 0;
  activeScanningPerformed: false;
  writeRequestsPerformed: 0;
  securityScoreChanged: false;
};
export type IsolatedSocketTransport = PassiveExecutionTransport & {
  readonly metrics: IsolatedNetworkMetrics;
  readonly scope: Readonly<IsolatedNetworkScope>;
};
export class IsolatedNetworkDenied extends Error {
  constructor(public readonly code: string) {
    super("Isolated passive transport denied: " + code);
  }
}
const isISO = (s: string) =>
  typeof s === "string" && Number.isFinite(Date.parse(s)) &&
  new Date(s).toISOString() === s;
const safeId = (s: string) =>
  typeof s === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:-]{3,127}$/.test(s);
const hex = (s: string) =>
  typeof s === "string" && /^[a-f0-9]{64}$/.test(s);
const publicAddress = (address: string) =>
  isIP(address) !== 0 && isPublicExposureAddress(address);
const unique = (values: string[]) => [...new Set(values)];
function deny(code: string): never {
  throw new IsolatedNetworkDenied(code);
}
function canonicalDomain(domain: string): boolean {
  return typeof domain === "string" &&
    domain.length >= 4 && domain.length <= 253 &&
    /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(domain) &&
    domain.includes(".") && !domain.includes("..") &&
    !domain.endsWith(".internal") && !domain.endsWith(".local");
}
function safeTimeout(ms: number): number {
  if (!Number.isSafeInteger(ms) || ms < 250 || ms > 4000)
    deny("UNBOUNDED_SOCKET_TIMEOUT");
  return ms;
}
function textBytes(values: string[]): number {
  return Buffer.byteLength(values.join("\n"),"utf8");
}
function boundedStrings(values: string[], max: number,
  eachMax = 512): string[] {
  if (values.length > 30 ||
      values.some(x => typeof x !== "string" ||
        x.length > eachMax ||
        /[\u0000-\u001f\u007f]/.test(x)) ||
      textBytes(values) > max)
    deny("DNS_RESPONSE_OVERSIZED_OR_MALFORMED");
  return values;
}
function sanitizeAddressSet(values: readonly string[]): string[] {
  const addresses = unique([...values]);
  if (!addresses.length || addresses.length > 8 ||
      addresses.some(x => !publicAddress(x)))
    deny("DNS_UNSAFE_PUBLIC_ADDRESS_SET");
  return addresses.sort();
}
function scopeValid(scope: IsolatedNetworkScope) {
  return safeId(scope.organizationId) &&
    safeId(scope.requestId) && safeId(scope.authorizationId) &&
    safeId(scope.grantId) && safeId(scope.leaseId) &&
    canonicalDomain(scope.domain) &&
    hex(scope.consentDigest) &&
    Number.isSafeInteger(scope.authorizationRevision) &&
    scope.authorizationRevision >= 1 &&
    Number.isSafeInteger(scope.maximumOperations) &&
    scope.maximumOperations >= 1 && scope.maximumOperations <= 10 &&
    isISO(scope.leaseExpiresAt) &&
    scope.leaseExpiresAt > new Date().toISOString() &&
    scope.executableByIndependentAuthority === true;
}
function operatorValid(operator: IsolatedNetworkOperator) {
  return operator.schema ===
    "cyberpilot.exposure.network.operator.v1" &&
    operator.liveFeatureEnabled === true &&
    operator.independentlyApprovedWorker === true &&
    operator.isolatedExecutionEnvironment === true &&
    operator.trustedQuotaAdapterPresent === true &&
    operator.scopedExecutionLeasePresent === true &&
    safeId(operator.operatorId);
}
export function validateIsolatedNetworkActivation(
  operator: IsolatedNetworkOperator,
  scope: IsolatedNetworkScope,
  env: NodeJS.ProcessEnv,
): string[] {
  const errors: string[] = [];
  if (env.CYBERPILOT_PASSIVE_LIVE_ENABLED !== "true")
    errors.push("LIVE_FEATURE_DISABLED");
  if (!operator || !operatorValid(operator))
    errors.push("OPERATOR_GUARD_INVALID");
  if (!scope || !scopeValid(scope))
    errors.push("INDEPENDENT_SCOPE_OR_LEASE_INVALID");
  if (env.LAB_AUTH_ENABLED === "true")
    errors.push("PUBLIC_LAB_AUTH_CANNOT_ARM_LIVE_TRANSPORT");
  return errors;
}
/**
 * This function does not make a socket connection. Callers must pass a
 * trusted independently operated quota/consent backend and a hard
 * activation gate. Public routes never invoke this factory.
 */
export function createIsolatedPassiveSocketTransport(
  operator: IsolatedNetworkOperator,
  scope: IsolatedNetworkScope,
  authority: IsolatedNetworkAuthorization,
  env: NodeJS.ProcessEnv = process.env,
): IsolatedSocketTransport {
  const activation = validateIsolatedNetworkActivation(
    operator, scope, env,
  );
  if (activation.length)
    deny(activation.join(","));
  if (!authority || authority.independentlyOperated !== true ||
      typeof authority.authorizeNetworkAction !== "function")
    deny("INDEPENDENT_EXECUTION_ADAPTER_MISSING");
  const metrics: IsolatedNetworkMetrics = {
    schema: "cyberpilot.exposure.network.metrics.v1",
    requestId: scope.requestId,
    organizationId: scope.organizationId,
    domain: scope.domain,
    dnsA: 0, dnsAAAA: 0, dnsTXT: 0, dnsMX: 0,
    tlsHandshakes: 0, headRequests: 0,
    totalAttempted: 0, totalAuthorized: 0,
    denied: 0, protocolErrors: 0, bytesAccepted: 0,
    lastErrorCode: null,
    passwordOrCookieSent: false,
    httpResponseBodyCollected: false,
    redirectedRequestsFollowed: 0,
    activeScanningPerformed: false,
    writeRequestsPerformed: 0,
    securityScoreChanged: false,
  };
  const resolver = new Resolver();
  const domain = scope.domain;
  const control = async (action: IsolatedNetworkAction,
    host: string, ip: string | null) => {
    metrics.totalAttempted += 1;
    if (metrics.totalAttempted > scope.maximumOperations ||
        scope.leaseExpiresAt <= new Date().toISOString()) {
      metrics.denied += 1;
      metrics.lastErrorCode = "LEASE_QUOTA_OR_TIME_EXCEEDED";
      deny("LEASE_QUOTA_OR_TIME_EXCEEDED");
    }
    if (host !== domain &&
        !(action === "DNS_TXT" && host === "_dmarc." + domain)) {
      metrics.denied += 1;
      metrics.lastErrorCode = "TARGET_OUTSIDE_SIGNED_SCOPE";
      deny("TARGET_OUTSIDE_SIGNED_SCOPE");
    }
    if (ip !== null && !publicAddress(ip)) {
      metrics.denied += 1;
      metrics.lastErrorCode = "PRIVATE_OR_RESERVED_PIN";
      deny("PRIVATE_OR_RESERVED_PIN");
    }
    let authorized = false;
    try {
      authorized = await authority.authorizeNetworkAction(
        scope, action, host, ip,
      );
    } catch { authorized = false; }
    if (!authorized) {
      metrics.denied += 1;
      metrics.lastErrorCode = "REVOKED_OR_QUOTA_DENIED";
      deny("REVOKED_OR_QUOTA_DENIED");
    }
    metrics.totalAuthorized += 1;
    switch (action) {
      case "DNS_A": metrics.dnsA++; break;
      case "DNS_AAAA": metrics.dnsAAAA++; break;
      case "DNS_TXT": metrics.dnsTXT++; break;
      case "DNS_MX": metrics.dnsMX++; break;
      case "TLS_CONNECT": metrics.tlsHandshakes++; break;
      case "HTTPS_HEAD": metrics.headRequests++; break;
    }
  };
  const resolvePublic = async (host: string, timeoutMs: number):
    Promise<string[]> => {
    safeTimeout(timeoutMs);
    await control("DNS_A",host,null);
    // Resolver timeout and retry are configured per instance. DNS
    // operations are separately charged, including AAAA.
    resolver.setServers([]);
    const timer = AbortSignal.timeout(timeoutMs);
    const lookup = async <T>(query: Promise<T>): Promise<T> =>
      Promise.race([
        query,
        new Promise<T>((_, reject) => timer.addEventListener(
          "abort", () => reject(
            new IsolatedNetworkDenied("DNS_TIMEOUT")),
          { once: true },
        )),
      ]);
    const v4 = await lookup(resolver.resolve4(host))
      .catch(() => [] as string[]);
    await control("DNS_AAAA",host,null);
    const v6 = await lookup(resolver.resolve6(host))
      .catch(() => [] as string[]);
    return sanitizeAddressSet([...v4,...v6]);
  };
  const collectDns = async (host: string,
    names: readonly string[], timeoutMs: number) => {
    safeTimeout(timeoutMs);
    if (host !== domain || names.length !== 2 ||
        names[0] !== domain || names[1] !== "_dmarc." + domain)
      deny("ARBITRARY_DNS_ENUMERATION_FORBIDDEN");
    const records: string[] = [];
    await control("DNS_TXT",domain,null);
    const txt = await Promise.race([
      resolver.resolveTxt(domain),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(
          new IsolatedNetworkDenied("DNS_TXT_TIMEOUT")),
        timeoutMs)),
    ]).catch(() => [] as string[][]);
    records.push(...txt.map(x => x.join("")));
    await control("DNS_TXT","_dmarc." + domain,null);
    const dmarc = await Promise.race([
      resolver.resolveTxt("_dmarc." + domain),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(
          new IsolatedNetworkDenied("DMARC_TIMEOUT")),
        timeoutMs)),
    ]).catch(() => [] as string[][]);
    records.push(...dmarc.map(x => x.join("")));
    await control("DNS_MX",domain,null);
    const mx = await Promise.race([
      resolver.resolveMx(domain),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(
          new IsolatedNetworkDenied("MX_TIMEOUT")),
        timeoutMs)),
    ]).catch(() => [] as Array<{priority:number;exchange:string}>);
    records.push(...mx.slice(0,10).map(x =>
      x.priority + " " + x.exchange));
    const bounded = boundedStrings(records,8192);
    const bytes = textBytes(bounded);
    metrics.bytesAccepted += bytes;
    return { records: bounded, bytes };
  };
  const collectTls = async (host: string,
    pinnedIp: string, timeoutMs: number): Promise<{
      peer: string; bytes: number; handshakeOnly: true;
    }> => {
    safeTimeout(timeoutMs);
    if (host !== domain || !publicAddress(pinnedIp))
      deny("TLS_TARGET_NOT_PINNED");
    await control("TLS_CONNECT",host,pinnedIp);
    return new Promise((resolve,reject) => {
      let settled = false;
      const socket = tlsConnect({
        host: pinnedIp, port: 443, servername: host,
        rejectUnauthorized: true,
        ALPNProtocols: ["http/1.1"],
      });
      const finish = (cause?: Error,
        result?: { peer:string; bytes:number;handshakeOnly:true }) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (cause) {
          metrics.protocolErrors += 1;
          metrics.lastErrorCode = "TLS_HANDSHAKE_OR_PEER_INVALID";
          reject(cause);
        } else if (result) resolve(result);
      };
      socket.setTimeout(timeoutMs,() =>
        finish(new IsolatedNetworkDenied("TLS_TIMEOUT")));
      socket.once("error",error => finish(error));
      socket.once("secureConnect",() => {
        const peer = socket.remoteAddress ?? "";
        if (!socket.authorized || peer !== pinnedIp)
          return finish(new IsolatedNetworkDenied(
            "TLS_UNTRUSTED_OR_UNPINNED_PEER"));
        metrics.bytesAccepted += 0;
        finish(undefined,{ peer, bytes:0, handshakeOnly:true });
      });
    });
  };
  const collectHead = async (url: string,
    pinnedIp: string, timeoutMs: number): Promise<{
      peer: string; bytes: number; method:"HEAD";
      redirectCount:0; bodyBytes:0; authenticated:false;
    }> => {
    safeTimeout(timeoutMs);
    if (url !== "https://" + domain + "/" ||
        !publicAddress(pinnedIp))
      deny("HEAD_URL_OR_IP_OUTSIDE_SIGNED_SCOPE");
    await control("HTTPS_HEAD",domain,pinnedIp);
    return new Promise((resolve,reject) => {
      let completed = false;
      let remoteAddress = "";
      const request = httpsRequest({
        hostname: domain,
        port:443,
        path:"/",
        protocol:"https:",
        method:"HEAD",
        agent:false,
        rejectUnauthorized:true,
        servername:domain,
        maxHeaderSize:8192,
        headers: {
          "Accept":"*/*",
          "User-Agent":"CyberPilot-Passive-Exposure/1",
          "Connection":"close",
        },
        lookup: (_hostname,_options,callback) =>
          callback(null,pinnedIp,isIP(pinnedIp)),
      },response => {
        const socketPeer = response.socket.remoteAddress ?? remoteAddress;
        const headerBytes = response.rawHeaders.reduce(
          (sum,value) => sum + Buffer.byteLength(value,"utf8")+4,0);
        // A 3xx response is a header observation only; never follow.
        // We destroy the stream immediately rather than consuming a body.
        response.destroy();
        if (!socketPeer || socketPeer !== pinnedIp ||
            headerBytes > 8192 ||
            response.headers["set-cookie"]?.length &&
              response.headers["set-cookie"]!.length > 32)
          return finish(new IsolatedNetworkDenied(
            "HEAD_PEER_OR_HEADERS_INVALID"));
        metrics.bytesAccepted += headerBytes;
        finish(undefined,{
          peer:socketPeer, bytes:headerBytes,
          method:"HEAD", redirectCount:0,
          bodyBytes:0, authenticated:false,
        });
      });
      const finish = (error?: Error,
        result?: {peer:string;bytes:number;method:"HEAD";
          redirectCount:0;bodyBytes:0;authenticated:false}) => {
        if (completed) return;
        completed = true;
        request.destroy();
        if (error) {
          metrics.protocolErrors++;
          metrics.lastErrorCode = "HEAD_SOCKET_OR_RESPONSE_INVALID";
          reject(error);
        } else if (result) resolve(result);
      };
      request.once("socket",socket => {
        socket.once("connect",() => {
          remoteAddress = socket.remoteAddress ?? "";
        });
      });
      request.once("error",error => finish(error));
      request.setTimeout(timeoutMs,() =>
        finish(new IsolatedNetworkDenied("HEAD_TIMEOUT")));
      request.end();
    });
  };
  return {
    scope: Object.freeze({...scope}),
    metrics,
    resolve: resolvePublic,
    collectDns,
    collectTls,
    collectHead,
  };
}
