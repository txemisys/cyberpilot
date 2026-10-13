# Render observability policy

This runbook defines the minimum operational observability policy for CyberPilot staging on Render.

It does not change the application event schema. CyberPilot continues to emit redacted JSON operational events to stdout/stderr.

## Platform collection

Render captures service stdout/stderr and exposes runtime logs centrally.

The first staging deployment must verify that CyberPilot JSON events are visible in the Render log explorer with their `level` and `event` fields intact.

At minimum, verify one controlled non-secret event from each available path without introducing a real customer incident.

Do not manufacture provider failures against a customer tenant merely to test logging.

## Required platform notifications

Before the first customer pilot, enable failure notifications for the staging service to an actively monitored destination.

Minimum platform events:

- failed build/deploy;
- service becomes unhealthy.

Email is acceptable for the first controlled pilot if ownership is explicit. Slack or a webhook may be added later.

## Application failure events to watch

CyberPilot currently emits structured events for:

- database health unavailable;
- Microsoft 365 inventory sync failure;
- scanner connection / tenant verification failure;
- remediation consent / capability verification failure;
- automated remediation execution failure;
- post-remediation verification sync failure.

For the first read-only pilot, the highest-priority application signals are:

1. repeated database health failures;
2. repeated Microsoft scanner connection failures;
3. repeated Microsoft sync failures;
4. unexpected HTTP 5xx increases from the platform.

LIVE remediation alerts remain defined but are not part of the first pilot because remediation credentials stay unset.

## Minimum incident ownership

Before pilot start, record one primary owner and one fallback contact for staging incidents.

The owner is responsible for:

- acknowledging platform failure notifications;
- checking Render events and logs;
- correlating application `eventId` values;
- deciding whether to pause the pilot;
- preserving only non-secret evidence needed for diagnosis.

Do not paste raw logs containing customer data into GitHub issues or chat.

## Retention and external streaming

Render's native logs are sufficient as the initial centralized staging collection layer only when their retention and access controls meet the pilot's operational needs.

Before broader production use, configure an external log stream when longer retention, cross-service correlation, stronger alerting or compliance requirements demand it.

Render supports forwarding service/datastore logs to third-party providers over TLS syslog or supported HTTPS integrations.

## Staging acceptance

Observability is accepted for the first pilot only after all of the following are verified on the provisioned Render service:

- structured JSON application events appear in Render logs;
- platform failure notifications are enabled and delivered to the named owner;
- `/api/health` failures result in service unhealthy visibility;
- no access tokens, refresh tokens, authorization headers, cookies, client secrets or raw Graph payloads appear in inspected logs;
- incident ownership is recorded;
- the team knows how to retrieve service events and logs during an incident.

This policy defines the gate; it does not claim the gate is complete until a real Render service is provisioned and tested.
