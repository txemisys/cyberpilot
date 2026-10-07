import { afterEach, describe, expect, it, vi } from "vitest";

import {
  hashOperationalIdentifier,
  reportOperationalEvent,
  sanitizeOperationalMetadata,
} from "./operational-logging";

describe("operational logging", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("redacts secret-bearing metadata recursively", () => {
    expect(
      sanitizeOperationalMetadata({
        accessToken: "should-not-leak",
        nested: {
          clientSecret: "also-secret",
          safeCode: "SYNC_FAILED",
        },
        authorization: "Bearer should-not-leak",
      }),
    ).toEqual({
      accessToken: "[REDACTED]",
      nested: {
        clientSecret: "[REDACTED]",
        safeCode: "SYNC_FAILED",
      },
      authorization: "[REDACTED]",
    });
  });

  it("hashes operational identifiers rather than logging raw IDs", () => {
    const hashed = hashOperationalIdentifier("organization-123");

    expect(hashed).toHaveLength(16);
    expect(hashed).not.toContain("organization-123");
  });

  it("does not log raw error messages", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const error = new Error("token=super-secret-provider-value");

    const record = reportOperationalEvent({
      event: "integration.sync_failed",
      organizationId: "organization-123",
      metadata: {
        failureCode: "SYNC_FAILED",
        password: "super-secret",
      },
      error,
    });

    const serialized = JSON.stringify(record);

    expect(serialized).toContain("SYNC_FAILED");
    expect(serialized).toContain("[REDACTED]");
    expect(serialized).not.toContain("super-secret");
    expect(serialized).not.toContain("provider-value");
    expect(serialized).not.toContain("organization-123");
    expect(record.error).toEqual({ name: "Error" });
    expect(spy).toHaveBeenCalledTimes(1);
  });
});
