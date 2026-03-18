# Search Operations Runbook

## Scope
Operational procedures for OpenSearch in Threat Intel Platform.

## Services
- OpenSearch: `tip-opensearch` on `localhost:9200`
- OpenSearch Dashboards: `tip-opensearch-dashboards` on `localhost:5601`

## Start / Stop
Start stack:
```powershell
docker compose -f docker/docker-compose.yml up -d
```

Check status:
```powershell
docker compose -f docker/docker-compose.yml ps
docker ps -a --filter "name=tip-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

Stop stack:
```powershell
docker compose -f docker/docker-compose.yml down
```

## Health Checks
Cluster health:
```powershell
Invoke-WebRequest -Uri "http://localhost:9200/_cluster/health" -UseBasicParsing
```

Dashboards health:
```powershell
Invoke-WebRequest -Uri "http://localhost:5601" -UseBasicParsing
```

Expected states:
- OpenSearch container: `healthy`
- Dashboards container: `healthy`
- `_cluster/health` response status: `green` or `yellow` for single-node local setups

## IOC Index Rebuild
Use this when mapping changes or index corruption occur.

1. Stop indexing workers (Celery worker stop).
2. Snapshot current index (optional in local dev):
```powershell
Invoke-WebRequest -Uri "http://localhost:9200/tip-iocs-v1/_search?size=0" -UseBasicParsing
```
3. Delete index:
```powershell
Invoke-WebRequest -Method Delete -Uri "http://localhost:9200/tip-iocs-v1" -UseBasicParsing
```
4. Recreate index mapping by running any endpoint/path that calls `ensure_ioc_index`.
5. Re-index from database by replaying IOC indexing tasks.

## Troubleshooting
Dashboards stuck in `starting`:
- Verify OpenSearch is healthy first.
- Check Dashboards logs:
```powershell
docker logs tip-opensearch-dashboards --tail 100
```
- Restart only dashboards:
```powershell
docker restart tip-opensearch-dashboards
```

OpenSearch unhealthy:
- Check logs:
```powershell
docker logs tip-opensearch --tail 100
```
- Validate host memory and Docker disk space.
- Ensure no port conflict on `9200`.

## Recovery Targets
- OpenSearch restore target (local): < 10 minutes
- IOC indexing catch-up target: < 15 minutes for 100k documents
