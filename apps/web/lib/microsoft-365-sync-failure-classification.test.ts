import { describe, expect, it } from "vitest";
import {
  MicrosoftGraphError,
  MicrosoftGraphPayloadError,
} from "@cyberpilot/integrations/microsoft-365";
import {
  getMicrosoft365SyncFailureCode,
  Microsoft365SyncLeaseLostError,
} from "./microsoft-365-sync";

describe("Microsoft 365 LIVE sync failure classification", () => {
  it.each([401, 403])("maps Graph HTTP %i to authorization failure", (status) => {
    expect(getMicrosoft365SyncFailureCode(new MicrosoftGraphError("No access", status)))
      .toBe("GRAPH_AUTHORIZATION_FAILED");
  });

  it("distinguishes throttling from transient Microsoft Graph unavailability", () => {
    expect(getMicrosoft365SyncFailureCode(new MicrosoftGraphError("Too many requests", 429)))
      .toBe("GRAPH_THROTTLED");
    for (const status of [500, 502, 503, 504]) {
      expect(getMicrosoft365SyncFailureCode(new MicrosoftGraphError("Unavailable", status)))
        .toBe("GRAPH_UNAVAILABLE");
    }
  });

  it("keeps invalid evidence and tenant mismatch separate from transient failures", () => {
    expect(getMicrosoft365SyncFailureCode(new MicrosoftGraphPayloadError("Unexpected Graph data")))
      .toBe("GRAPH_PAYLOAD_INVALID");
    expect(getMicrosoft365SyncFailureCode(new Error("Microsoft tenant verification failed during sync.")))
      .toBe("TENANT_MISMATCH");
  });

  it("reports lost synchronization ownership distinctly", () => {
    expect(getMicrosoft365SyncFailureCode(new Microsoft365SyncLeaseLostError()))
      .toBe("SYNC_LEASE_LOST");
  });

  it("fails safely with a generic classification for unknown Graph failures", () => {
    expect(getMicrosoft365SyncFailureCode(new MicrosoftGraphError("Unrecognized status", 418)))
      .toBe("SYNC_FAILED");
    expect(getMicrosoft365SyncFailureCode(new Error("Unexpected internal failure")))
      .toBe("SYNC_FAILED");
  });
});
