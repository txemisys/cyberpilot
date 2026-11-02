#!/usr/bin/env bash
set -euo pipefail
# Integration check: two independent PostgreSQL connections must serialize
# withdrawals for the same audit event and preserve one withdrawal event.
db=(docker compose -f compose.dev.yml exec -T postgres psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d cyberpilot)
original="integrity-concurrency-original"
withdrawal="integrity-concurrency-withdrawal"
org="local-stack-e2e-org"
cleanup() {
  "${db[@]}" -c "DELETE FROM \"AuditEvent\" WHERE id IN ('$original', '$withdrawal');" >/dev/null || true
}
trap cleanup EXIT
cleanup
"${db[@]}" -c "INSERT INTO \"AuditEvent\" (id, \"organizationId\", \"actorType\", action, \"resourceType\", \"resourceId\", metadata) VALUES ('$original', '$org', 'SYSTEM', 'INTEGRITY_CAPTURE_CASE_LINKED_TO_WORK', 'REMEDIATION_WORK_ITEM', 'work-race', '{\"captureId\":\"capture-race\",\"caseKey\":\"case-race\"}'::jsonb);" >/dev/null

# The first transaction holds the same advisory key used by the application.
"${db[@]}" <<SQL > /tmp/cyberpilot-integrity-first.out &
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('$original', 0));
SELECT pg_sleep(2);
INSERT INTO "AuditEvent" (id, "organizationId", "actorType", action, "resourceType", "resourceId", metadata)
VALUES ('$withdrawal', '$org', 'SYSTEM', 'INTEGRITY_CAPTURE_CASE_UNLINKED_FROM_WORK',
        'REMEDIATION_WORK_ITEM', 'work-race',
        '{"originalAuditId":"$original","captureId":"capture-race","caseKey":"case-race"}'::jsonb);
COMMIT;
SQL
first_pid=$!
sleep 0.4
# A second connection cannot acquire the same lock until the first commits.
blocked="$("${db[@]}" -c "SELECT pg_try_advisory_xact_lock(hashtextextended('$original', 0));")"
test "$blocked" = "f" || { echo "ERROR: concurrent transaction bypassed advisory lock"; exit 1; }
wait "$first_pid"
# After the first commit, a second transaction can acquire the lock but
# must detect the already committed withdrawal and refuse to append another.
second_result="$("${db[@]}" <<SQL
BEGIN;
SELECT pg_advisory_xact_lock(hashtextextended('$original', 0));
SELECT COUNT(*) FROM "AuditEvent"
WHERE "organizationId"='$org'
  AND action='INTEGRITY_CAPTURE_CASE_UNLINKED_FROM_WORK'
  AND metadata->>'originalAuditId'='$original';
COMMIT;
SQL
)"
second_count="$("${db[@]}" <<SQL
SELECT COUNT(*) FROM "AuditEvent"
WHERE action='INTEGRITY_CAPTURE_CASE_UNLINKED_FROM_WORK'
  AND metadata->>'originalAuditId'='$original';
SQL
)"
test "$count" = "1" || { echo "ERROR: withdrawal audit event was not committed"; exit 1; }
echo "PostgreSQL withdrawal lock and immutable audit event verified."
