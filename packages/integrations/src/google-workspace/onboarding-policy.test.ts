import { describe, expect, it } from "vitest";
import {
  newGoogleLabConnection, transitionGoogleLab,
  verifyGoogleLabConnection, verifyGoogleLabEvents,
  inspectGoogleLabEligibility, replayGoogleLabHistory,
  digestChallengeNonce, parseGoogleLabPolicy,
  redactGoogleLabConnection,
  type GoogleLabScope, type GoogleLabEvent,
} from "./onboarding-policy";
import {
  GoogleLabOnboardingService,
  type GoogleLabRepository,
} from "./onboarding-orchestrator";
const organizationId = "lab-org-12345";
const userId = "lab-admin-12345";
const scope: GoogleLabScope = {
  organizationId, actorUserId: userId, role: "ADMIN",
};
const nonce = "synthetic-safe-challenge-123456789012345678901234";
const day = (offset: number) =>
  new Date(Date.parse("2026-11-12T10:00:00Z") +
    offset * 60000).toISOString();
function initial() {
  return newGoogleLabConnection(scope, "google-lab-12345", day(0));
}
function command(type: "ISSUE_CHALLENGE" | "ACCEPT_LAB" | "DENY_CONSENT" |
  "REVOKE" | "SUSPEND" | "RESUME" | "EXPIRE", revision: number,
  offset: number, previousEventDigest?: string) {
  return {
    type, connectionId: "google-lab-12345",
    expectedRevision: revision, at: day(offset),
    reason: "Validated test operator rationale.",
    challengeNonce: nonce,
    requestedCapabilities: ["DIRECTORY_USERS" as const],
    ...(previousEventDigest ?
      { previousEventDigest } : {}),
  };
}
describe("Google Workspace LAB deterministic onboarding", () => {
  it("creates an unsigned tenant-scoped unconfigured connection", () => {
    const state = initial();
    expect(state.state).toBe("NOT_CONFIGURED");
    expect(state.revision).toBe(0);
    expect(state.credentialStored).toBe(false);
    expect(state.liveProviderConnected).toBe(false);
    expect(verifyGoogleLabConnection(state).valid).toBe(true);
  });
  it("issues, consumes and audits one local challenge without Google API", () => {
    const started = initial();
    const issued = transitionGoogleLab(started, scope,
      command("ISSUE_CHALLENGE", 0, 1));
    expect(issued.connection.state).toBe("CHALLENGE_ISSUED");
    expect(JSON.stringify(issued)).not.toContain(nonce);
    const accepted = transitionGoogleLab(issued.connection, scope,
      command("ACCEPT_LAB", 1, 2, issued.event.digest),
      issued.event);
    expect(accepted.connection.state).toBe("CONNECTED_LAB");
    expect(accepted.connection.permittedCapabilities)
      .toEqual(["DIRECTORY_USERS"]);
    expect(accepted.sideEffects.googleApiRequests).toBe(0);
    expect(verifyGoogleLabEvents(accepted.connection,
      [issued.event, accepted.event]).valid).toBe(true);
    expect(replayGoogleLabHistory(started,
      [issued.event, accepted.event]).valid).toBe(true);
    expect(inspectGoogleLabEligibility(accepted.connection,
      scope, day(3), ["DIRECTORY_USERS"]).eligible).toBe(true);
    expect(inspectGoogleLabEligibility(accepted.connection,
      scope, day(3), ["REPORTS_ADMIN"]).eligible).toBe(false);
  });
  it("refuses incorrect nonce, replay and cross-tenant access", () => {
    const start = initial();
    const issued = transitionGoogleLab(start, scope,
      command("ISSUE_CHALLENGE", 0, 1));
    expect(() => transitionGoogleLab(issued.connection, scope,
      { ...command("ACCEPT_LAB", 1, 2, issued.event.digest),
        challengeNonce: "wrong-challenge-xxxxxxxxxxxxxxxxxxxxxxxx" },
      issued.event)).toThrow();
    expect(() => transitionGoogleLab(issued.connection, {
      ...scope, organizationId: "foreign-org-12345",
    }, command("ACCEPT_LAB", 1, 2, issued.event.digest),
    issued.event)).toThrow();
    const accepted = transitionGoogleLab(issued.connection, scope,
      command("ACCEPT_LAB", 1, 2, issued.event.digest),
      issued.event);
    expect(() => transitionGoogleLab(accepted.connection, scope,
      command("ACCEPT_LAB", 2, 3, accepted.event.digest),
      accepted.event)).toThrow();
  });
  it("expires a connection without preserving fixture eligibility", () => {
    const issued = transitionGoogleLab(initial(), scope,
      command("ISSUE_CHALLENGE", 0, 1));
    const accepted = transitionGoogleLab(issued.connection, scope,
      command("ACCEPT_LAB", 1, 2, issued.event.digest),
      issued.event);
    expect(inspectGoogleLabEligibility(accepted.connection, scope,
      day(60 * 24 * 31), ["DIRECTORY_USERS"]).eligible).toBe(false);
  });
  it("denied lab consent cannot be presented as Google consent", () => {
    const issued = transitionGoogleLab(initial(), scope,
      command("ISSUE_CHALLENGE", 0, 1));
    const denied = transitionGoogleLab(issued.connection, scope,
      command("DENY_CONSENT", 1, 2, issued.event.digest),
      issued.event);
    expect(denied.connection.state).toBe("CONSENT_DENIED");
    expect(denied.connection.permittedCapabilities).toHaveLength(0);
    expect(denied.connection.administratorConsentVerified).toBe(false);
  });
  it("prevents downgrading mandatory safety policy", () => {
    for (const unsafe of [
      { allowRealGoogleOauth: true },
      { allowExternalGoogleProvider: true },
      { allowAccountWrites: true },
      { customerConsentNotAttested: false },
      { requireIndependentReviewerForLive: false },
      { maxEvents: 0 },
    ]) expect(() => parseGoogleLabPolicy(unsafe)).toThrow();
  });
  it("keeps raw nonce out of the redacted connection and events", () => {
    const issued = transitionGoogleLab(initial(), scope,
      command("ISSUE_CHALLENGE", 0, 1));
    const redacted = redactGoogleLabConnection(issued.connection);
    expect(JSON.stringify(redacted)).not.toContain(nonce);
    expect(JSON.stringify(issued.event)).not.toContain(nonce);
    expect(issued.connection.challenge?.challengeDigest).toBe(
      digestChallengeNonce(organizationId, "google-lab-12345", nonce));
  });
});
class FakeAtomicStore implements GoogleLabRepository {
  state: ReturnType<typeof initial> | null = null;
  events: GoogleLabEvent[] = [];
  async createInitial(_scope: GoogleLabScope,
    state: ReturnType<typeof initial>) {
    if (this.state) throw new Error("Already exists");
    this.state = state; return state;
  }
  async getByOrganization(org: string, id: string) {
    return this.state?.organizationId === org &&
      this.state.id === id ? this.state : null;
  }
  async getEventHead(org: string, id: string) {
    return this.events.filter(e => e.organizationId === org &&
      e.connectionId === id).at(-1) ?? null;
  }
  async compareAndSwap(old: ReturnType<typeof initial>,
    transition: ReturnType<typeof transitionGoogleLab>) {
    if (this.state?.stateDigest !== old.stateDigest)
      throw new Error("Concurrent mutation");
    this.state = transition.connection;
    this.events.push(transition.event);
    return this.state;
  }
  async getEvents(org: string, id: string,
    offset: number, limit: number) {
    return this.events.filter(e => e.organizationId === org &&
      e.connectionId === id).slice(offset, offset + limit);
  }
  async list(org: string, offset: number, limit: number) {
    return this.state?.organizationId === org ?
      [this.state].slice(offset, offset + limit) : [];
  }
}
describe("Google LAB onboarding repository boundary", () => {
  it("requires atomic storage and returns tenant-redacted results", async () => {
    const store = new FakeAtomicStore();
    const service = new GoogleLabOnboardingService(store);
    const result = await service.create(scope, {
      connectionId: "google-lab-12345",
      createdAt: day(0), requestKey: "google-create-12345",
    });
    expect(result.created).toBe(true);
    const initialView = await service.get(scope,
      "google-lab-12345", day(1));
    expect(initialView.connection.liveProviderConnected).toBe(false);
    const issued = await service.mutate(scope,
      command("ISSUE_CHALLENGE", 0, 1));
    const accepted = await service.mutate(scope,
      command("ACCEPT_LAB", 1, 2, issued.receipt.eventDigest));
    expect(accepted.connection.state).toBe("CONNECTED_LAB");
    const audit = await service.audit(scope,
      "google-lab-12345", day(3));
    expect(audit.chainVerified).toBe(true);
    expect(audit.customerConsentLegallyAttested).toBe(false);
    const list = await service.list(scope);
    expect(list.items).toHaveLength(1);
    expect(list.crossTenantResultsPossible).toBe(false);
  });
  it("blocks member mutation and outsider tenant reads", async () => {
    const store = new FakeAtomicStore();
    const service = new GoogleLabOnboardingService(store);
    await service.create(scope, {
      connectionId: "google-lab-12345",
      createdAt: day(0), requestKey: "google-create-12345",
    });
    await expect(service.mutate({
      ...scope, role: "MEMBER",
    }, command("ISSUE_CHALLENGE", 0, 1))).rejects.toThrow();
    await expect(service.get({
      ...scope, organizationId: "foreign-org-12345",
    }, "google-lab-12345")).rejects.toThrow();
  });
});
