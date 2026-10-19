export type Microsoft365SyncStatusMessage = {
  title: string;
  guidance: string;
};

export function getMicrosoft365SyncStatusMessage(
  code: string | null | undefined,
): Microsoft365SyncStatusMessage {
  switch (code) {
    case "GRAPH_AUTHORIZATION_FAILED":
      return {
        title: "Microsoft access needs attention",
        guidance:
          "Run the read-only Microsoft access test again. If it still fails, verify admin consent for the documented scanner permissions.",
      };
    case "GRAPH_PAYLOAD_INVALID":
      return {
        title: "Microsoft returned unexpected data",
        guidance:
          "Retry the sync. If the issue repeats, review CyberPilot operational logs using the event ID without copying Graph payloads or tenant data.",
      };
    case "GRAPH_THROTTLED":
      return {
        title: "Microsoft temporarily throttled the sync",
        guidance:
          "Retry later. CyberPilot already applies bounded Retry-After/backoff handling before reporting this failure.",
      };
    case "GRAPH_UNAVAILABLE":
      return {
        title: "Microsoft Graph is temporarily unavailable",
        guidance:
          "Retry the sync after the service recovers. The last successful CyberPilot snapshot remains unchanged.",
      };
    case "SYNC_LEASE_LOST":
      return {
        title: "The sync lost its execution lease",
        guidance:
          "CyberPilot stopped before publishing any new snapshot because another execution took ownership. Retry the sync; the previous successful snapshot remains unchanged.",
      };
    case "TENANT_MISMATCH":
      return {
        title: "Microsoft tenant verification failed",
        guidance:
          "Do not retry blindly. Reconnect the intended tenant and verify the scanner consent belongs to the same Microsoft tenant.",
      };
    case "SYNC_FAILED":
      return {
        title: "The Microsoft 365 sync failed safely",
        guidance:
          "Retry once. If it repeats, inspect the redacted operational event and its event ID; the previous successful snapshot is preserved.",
      };
    default:
      return {
        title: "The latest Microsoft 365 operation reported an issue",
        guidance:
          "Retry the operation. If it repeats, inspect the redacted operational logs without copying customer data into support channels.",
      };
  }
}
