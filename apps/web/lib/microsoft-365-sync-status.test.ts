import { describe, expect, it } from "vitest";

import { getMicrosoft365SyncStatusMessage } from "./microsoft-365-sync-status";

describe("getMicrosoft365SyncStatusMessage", () => {
  it("returns actionable guidance for authorization failures", () => {
    expect(
      getMicrosoft365SyncStatusMessage("GRAPH_AUTHORIZATION_FAILED"),
    ).toEqual({
      title: "Microsoft access needs attention",
      guidance:
        "Run the read-only Microsoft access test again. If it still fails, verify admin consent for the documented scanner permissions.",
    });
  });

  it("does not expose raw upstream error details for unknown codes", () => {
    const message = getMicrosoft365SyncStatusMessage(
      "secret tenant payload from upstream",
    );

    expect(message.title).not.toContain("secret");
    expect(message.guidance).not.toContain("secret");
    expect(message.guidance).toContain("redacted operational logs");
  });

  it("explains that a transient Graph outage preserves the previous snapshot", () => {
    expect(
      getMicrosoft365SyncStatusMessage("GRAPH_UNAVAILABLE").guidance,
    ).toContain("last successful CyberPilot snapshot remains unchanged");
  });
});


  it("explains lease fencing without suggesting partial data was published", () => {
    const message = getMicrosoft365SyncStatusMessage("SYNC_LEASE_LOST");

    expect(message.title).toContain("lease");
    expect(message.guidance).toContain("stopped before publishing");
    expect(message.guidance).toContain("previous successful snapshot remains unchanged");
  });
