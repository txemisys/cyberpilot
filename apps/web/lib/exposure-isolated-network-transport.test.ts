import { describe, expect, it, vi } from "vitest";
import {
  createIsolatedPassiveSocketTransport,
  validateIsolatedNetworkActivation,
  IsolatedNetworkDenied,
  type IsolatedNetworkOperator,
  type IsolatedNetworkScope,
  type IsolatedNetworkAuthorization,
} from "./exposure-isolated-network-transport";
const operator: IsolatedNetworkOperator = {
  schema: "cyberpilot.exposure.network.operator.v1",
  liveFeatureEnabled: true,
  operatorId: "network-operator",
  independentlyApprovedWorker: true,
  isolatedExecutionEnvironment: true,
  trustedQuotaAdapterPresent: true,
  scopedExecutionLeasePresent: true,
};
function scope(): IsolatedNetworkScope {
  return {
    organizationId: "org-test",
    requestId: "request-test",
    domain: "example.com",
    authorizationId: "authorization-test",
    authorizationRevision: 1,
    grantId: "grant-test",
    consentDigest: "a".repeat(64),
    leaseId: "lease-test",
    leaseExpiresAt: new Date(Date.now()+120000).toISOString(),
    maximumOperations: 10,
    executableByIndependentAuthority: true,
  };
}
function authority(): IsolatedNetworkAuthorization {
  return {
    independentlyOperated: true,
    authorizeNetworkAction: vi.fn(async () => false),
  };
}
const liveEnv = {
  CYBERPILOT_PASSIVE_LIVE_ENABLED: "true",
  LAB_AUTH_ENABLED: "false",
};
describe("network adapter hard activation and no outbound by default", () => {
  it("rejects absent operator opt-in", () => {
    const result = validateIsolatedNetworkActivation(
      operator,scope(),{},
    );
    expect(result).toContain("LIVE_FEATURE_DISABLED");
    expect(() => createIsolatedPassiveSocketTransport(
      operator,scope(),authority(),{},
    )).toThrow(IsolatedNetworkDenied);
  });
  it("rejects any LAB-authenticated worker regardless of declared consent", () => {
    expect(validateIsolatedNetworkActivation(
      operator,scope(),{
        CYBERPILOT_PASSIVE_LIVE_ENABLED:"true",
        LAB_AUTH_ENABLED:"true",
      },
    )).toContain("PUBLIC_LAB_AUTH_CANNOT_ARM_LIVE_TRANSPORT");
  });
  it("rejects arbitrary expired leases before network", () => {
    const bad = scope();
    bad.leaseExpiresAt = new Date(Date.now()-1000).toISOString();
    expect(validateIsolatedNetworkActivation(
      operator,bad,liveEnv,
    )).toContain("INDEPENDENT_SCOPE_OR_LEASE_INVALID");
  });
  it("rejects a forged or unaudited operator gate", () => {
    const bad = { ...operator, isolatedExecutionEnvironment:false as true };
    expect(validateIsolatedNetworkActivation(bad,scope(),liveEnv))
      .toContain("OPERATOR_GUARD_INVALID");
  });
  it("requires independently operated authorization callback", () => {
    expect(() => createIsolatedPassiveSocketTransport(
      operator,scope(),{
        independentlyOperated:false as true,
        authorizeNetworkAction:vi.fn(async () => true),
      },liveEnv,
    )).toThrow(/INDEPENDENT_EXECUTION_ADAPTER_MISSING/);
  });
  it("denies DNS before any external resolution when authority rejects", async () => {
    const gate = authority();
    const worker = createIsolatedPassiveSocketTransport(
      operator,scope(),gate,liveEnv,
    );
    await expect(worker.resolve("example.com",4000))
      .rejects.toThrow(/REVOKED_OR_QUOTA_DENIED/);
    expect(gate.authorizeNetworkAction)
      .toHaveBeenCalledTimes(1);
    expect(worker.metrics.dnsA).toBe(0);
    expect(worker.metrics.totalAuthorized).toBe(0);
    expect(worker.metrics.denied).toBe(1);
  });
  it("blocks private and reserved TLS pins even with an authority", async () => {
    const gate = authority();
    const worker = createIsolatedPassiveSocketTransport(
      operator,scope(),gate,liveEnv,
    );
    await expect(worker.collectTls("example.com","127.0.0.1",4000))
      .rejects.toThrow(/TLS_TARGET_NOT_PINNED/);
    expect(gate.authorizeNetworkAction).not.toHaveBeenCalled();
    expect(worker.metrics.tlsHandshakes).toBe(0);
  });
  it("blocks arbitrary HTTPS paths without network or redirects", async () => {
    const gate = authority();
    const worker = createIsolatedPassiveSocketTransport(
      operator,scope(),gate,liveEnv,
    );
    await expect(worker.collectHead(
      "https://example.com/admin","8.8.8.8",4000,
    )).rejects.toThrow(/HEAD_URL_OR_IP_OUTSIDE_SIGNED_SCOPE/);
    expect(gate.authorizeNetworkAction).not.toHaveBeenCalled();
    expect(worker.metrics.redirectedRequestsFollowed).toBe(0);
    expect(worker.metrics.httpResponseBodyCollected).toBe(false);
  });
  it("blocks DNS enumeration outside the signed APEX + DMARC names", async () => {
    const gate = authority();
    const worker = createIsolatedPassiveSocketTransport(
      operator,scope(),gate,liveEnv,
    );
    await expect(worker.collectDns(
      "example.com",["example.com","admin.example.com"],4000,
    )).rejects.toThrow(/ARBITRARY_DNS_ENUMERATION_FORBIDDEN/);
    expect(gate.authorizeNetworkAction).not.toHaveBeenCalled();
  });
  it("bounds timeouts before each authorized operation", async () => {
    const gate = authority();
    const worker = createIsolatedPassiveSocketTransport(
      operator,scope(),gate,liveEnv,
    );
    await expect(worker.resolve("example.com",60000))
      .rejects.toThrow(/UNBOUNDED_SOCKET_TIMEOUT/);
    expect(gate.authorizeNetworkAction).not.toHaveBeenCalled();
  });
});
