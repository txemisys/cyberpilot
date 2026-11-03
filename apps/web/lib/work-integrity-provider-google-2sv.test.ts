import { describe, expect, it, vi } from "vitest";
import {
  checkGoogle2SvResponse, evaluateGoogle2Sv,
  parseGoogle2SvObservation, parseProviderCheckInput,
  parseProviderCheckQuery, readGoogleWorkspaceUser,
} from "./work-integrity-provider-google-2sv";

const customerId = "C123456789";
const subject = "admin@example.invalid";
const observation = {
  id: "google-user-12345",
  customerId, primaryEmail: subject,
  isEnrolledIn2Sv: true,
  isEnforcedIn2Sv: true,
  suspended: false,
  archived: false,
  etag: "etag-123",
};
const input = {
  taskId: "review-task-12345",
  evidenceId: "evidence-item-12345",
  subject, expectedCustomerId: customerId,
  requestKey: "provider-check-12345",
  accessToken: "test-token-value-1234567890",
};
const read = {
  status: 200, response: observation,
  receivedAt: new Date("2026-11-03T10:00:00.000Z"),
};
describe("Google Workspace 2SV provider input", () => {
  it("accepts a scoped provider verification request", () => {
    expect(parseProviderCheckInput(input)).toEqual(input);
  });
  it.each([
    { taskId: "bad" },
    { evidenceId: "bad" },
    { subject: "https://evil.invalid" },
    { subject: "../admin" },
    { expectedCustomerId: "tenant" },
    { expectedCustomerId: "C12345\n" },
    { requestKey: "short" },
    { accessToken: "short" },
    { accessToken: "test-token-1234567890\n" },
    { unexpected: true },
  ])("rejects invalid provider request %j", patch => {
    expect(() => parseProviderCheckInput({ ...input, ...patch })).toThrow();
  });
  it("accepts bounded query defaults", () => {
    expect(parseProviderCheckQuery({ taskId: input.taskId })).toEqual({
      taskId: input.taskId, offset: 0, limit: 50,
    });
  });
  it.each([
    { offset: -1 }, { offset: "0" },
    { limit: 0 }, { limit: 201 },
    { extra: true },
  ])("rejects invalid history query %j", patch => {
    expect(() => parseProviderCheckQuery({
      taskId: input.taskId, ...patch,
    })).toThrow();
  });
});
describe("Google Directory 2SV interpretation", () => {
  it("parses a complete Google user", () => {
    expect(parseGoogle2SvObservation(observation)).toEqual(observation);
  });
  it("does not invent missing Boolean values", () => {
    const result = parseGoogle2SvObservation({
      ...observation, isEnrolledIn2Sv: undefined,
      isEnforcedIn2Sv: "true",
    });
    expect(result.isEnrolledIn2Sv).toBeNull();
    expect(result.isEnforcedIn2Sv).toBeNull();
  });
  it("passes only enrollment and enforcement both true", () => {
    expect(evaluateGoogle2Sv(
      observation, customerId, subject,
    ).outcome).toBe("PASS");
  });
  it.each([
    { isEnrolledIn2Sv: false },
    { isEnforcedIn2Sv: false },
    { isEnrolledIn2Sv: false, isEnforcedIn2Sv: false },
  ])("fails when 2SV protection is absent %j", patch => {
    expect(evaluateGoogle2Sv({
      ...observation, ...patch,
    }, customerId, subject).outcome).toBe("FAIL");
  });
  it.each([
    { isEnrolledIn2Sv: null },
    { isEnforcedIn2Sv: null },
    { suspended: true },
    { archived: true },
    { customerId: "C987654321" },
    { primaryEmail: "other@example.invalid" },
  ])("is inconclusive for incomplete or mismatched identity %j", patch => {
    expect(evaluateGoogle2Sv({
      ...observation, ...patch,
    }, customerId, subject).outcome).toBe("INCONCLUSIVE");
  });
  it("records provider response digest without storing raw response", () => {
    const result = checkGoogle2SvResponse(read, customerId, subject);
    expect(result.outcome).toBe("PASS");
    expect(result.responseDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.observedAt).toEqual(read.receivedAt);
    expect('customerId' in result.metadata && result.metadata.customerId).toBe(customerId);
  });
  it.each([401, 403, 404, 429, 500, 503])(
    "does not treat provider HTTP %s as a passing observation", status => {
      const result = checkGoogle2SvResponse({
        ...read, status, response: { error: "not authorized" },
      }, customerId, subject);
      expect(result.outcome).toBe("PROVIDER_ERROR");
      expect(result.failureCode).toBeTruthy();
    },
  );
  it("rejects malformed success response conservatively", () => {
    const result = checkGoogle2SvResponse({
      ...read, response: { id: "user", primaryEmail: subject },
    }, customerId, subject);
    expect(result.outcome).toBe("INCONCLUSIVE");
    expect(result.failureCode).toBe("INVALID_PROVIDER_RESPONSE");
  });
});
describe("Google Directory HTTP read boundary", () => {
  it("uses fixed HTTPS host, GET, no redirects and bearer token", async () => {
    const fetcher = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(JSON.stringify(observation), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
    const result = await readGoogleWorkspaceUser(
      subject, input.accessToken,
      { fetcher: fetcher as unknown as typeof fetch },
    );
    expect(result.status).toBe(200);
    expect(fetcher).toHaveBeenCalledOnce();
    const [url, init] = fetcher.mock.calls[0]!;
    expect(url).toMatch(/^https:\/\/admin.googleapis.com\/admin\/directory\/v1\/users\//);
    expect(url).toContain(encodeURIComponent(subject));
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    expect(init?.cache).toBe("no-store");
    expect((init?.headers as Record<string, string>).Authorization)
      .toBe("Bearer " + input.accessToken);
  });
  it("does not follow arbitrary provider URLs", async () => {
    const fetcher = vi.fn();
    await expect(readGoogleWorkspaceUser(
      "../evil", input.accessToken,
      { fetcher: fetcher as unknown as typeof fetch },
    )).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("rejects oversized remote response", async () => {
    const fetcher = vi.fn(async () => new Response("x".repeat(128001)));
    await expect(readGoogleWorkspaceUser(
      subject, input.accessToken,
      { fetcher: fetcher as unknown as typeof fetch },
    )).rejects.toThrow();
  });
  it("rejects invalid JSON returned with success", async () => {
    const fetcher = vi.fn(async () => new Response("{", { status: 200 }));
    await expect(readGoogleWorkspaceUser(
      subject, input.accessToken,
      { fetcher: fetcher as unknown as typeof fetch },
    )).rejects.toThrow();
  });
});
