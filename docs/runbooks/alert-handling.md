# Alert Handling Runbook

## Scope
Operational response for ingestion/search/indexing pipeline alerts.

## Alert Types
- `ingestion_failure`
- `indexing_failure`
- `search_failure`
- `index_lag`
- `entitlement_violation`
- `quota_exceeded`

All alerts include `request_id` when available.

## Triage Steps
1. Identify alert severity and affected org.
2. Extract `request_id` from alert payload.
3. Query application logs for the `request_id`.
4. Confirm whether failure is transient or systemic.
5. Apply type-specific remediation.

## Type-Specific Actions
### ingestion_failure
- Validate upstream feed availability.
- Inspect `feed_ingestion` logs.
- Retry single source ingestion.

### indexing_failure
- Check OpenSearch health.
- Validate index exists and mapping is intact.
- Replay failed IOC indexing task.

### search_failure
- Confirm OpenSearch query latency and status.
- Check API service logs for malformed query/filter payloads.
- Verify tenant filter (`org_id`) is present.

### entitlement_violation
- Confirm organization plan and enabled features.
- Verify expected denial behavior (e.g., STIX export for free plan).
- Escalate if behavior differs from plan policy.

### quota_exceeded
- Confirm plan quota values.
- Identify burst patterns or abuse.
- Recommend plan upgrade or quota adjustment.

## Correlation Workflow
Given an alert with `request_id`:
1. API logs: find request envelope and endpoint.
2. Audit events: locate action/resource for same request.
3. Celery logs: verify task enqueue and execution status.
4. Integration logs (Splunk/Elastic push): validate outbound sink results.

## Escalation Criteria
- P1: Cross-tenant data exposure risk, repeated indexing failures > 10 minutes.
- P2: Search API degradation > 5% failures over 5 minutes.
- P3: Single feed transient failures with auto-recovery.
