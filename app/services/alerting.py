"""
Observability and alerting service for the search infrastructure.

Supports:
- Slack webhooks
- Email alerts
- Generic webhooks (SIEM/SOAR/custom integrations)
- Alert aggregation and deduplication
- Request ID tracing for quick root cause analysis
"""

import json
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from uuid import UUID

import requests
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.logging import logger
from app.config import (
    SLACK_WEBHOOK_URL,
    EMAIL_RECIPIENTS,
    WEBHOOK_URLS,
)


class AlertSeverity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AlertType:
    INDEXING_FAILURE = "indexing_failure"
    INGESTION_FAILURE = "ingestion_failure"
    SEARCH_FAILURE = "search_failure"
    INDEX_LAG = "index_lag"
    ENTITLEMENT_VIOLATION = "entitlement_violation"
    AUTH_FAILURE = "auth_failure"
    QUOTA_EXCEEDED = "quota_exceeded"


class Alert:
    """Alert event with context for observability."""
    
    def __init__(
        self,
        alert_type: str,
        severity: str,
        title: str,
        description: str,
        org_id: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.alert_type = alert_type
        self.severity = severity
        self.title = title
        self.description = description
        self.org_id = org_id
        self.request_id = request_id
        self.details = details or {}
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "org_id": str(self.org_id) if self.org_id else None,
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }


class AlertManager:
    """Manages routing of alerts to configured sinks."""
    
    def __init__(self):
        self.slack_webhook = SLACK_WEBHOOK_URL
        self.email_recipients = EMAIL_RECIPIENTS or []
        self.webhook_urls = WEBHOOK_URLS or []
        self.alert_history: List[Dict[str, Any]] = []
    
    async def send_alert(self, alert: Alert) -> bool:
        """Send alert to all configured sinks."""
        
        logger.info(
            f"Sending alert: {alert.alert_type}",
            extra={
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "request_id": alert.request_id,
            },
        )
        
        # Store in history for deduplication
        self.alert_history.append(alert.to_dict())
        
        # Keep only last 1000 alerts in history
        if len(self.alert_history) > 1000:
            self.alert_history = self.alert_history[-1000:]
        
        # Send to all configured sinks
        tasks = []
        
        if self.slack_webhook:
            tasks.append(self._send_to_slack(alert))
        
        if self.email_recipients:
            tasks.append(self._send_email(alert))
        
        for webhook_url in self.webhook_urls:
            tasks.append(self._send_to_webhook(alert, webhook_url))
        
        # Execute all sends concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success = all(r is not True for r in results if not isinstance(r, Exception))
            return success
        
        return True
    
    async def _send_to_slack(self, alert: Alert) -> bool:
        """Send alert to Slack webhook."""
        try:
            payload = {
                "text": f"🚨 [{alert.severity.upper()}] {alert.title}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"Alert: {alert.alert_type}"},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity*\n{alert.severity}"},
                            {"type": "mrkdwn", "text": f"*Type*\n{alert.alert_type}"},
                            {"type": "mrkdwn", "text": f"*Org*\n{alert.org_id or 'N/A'}"},
                            {"type": "mrkdwn", "text": f"*Request ID*\n`{alert.request_id or 'N/A'}`"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Description*\n{alert.description}"},
                    },
                    {
                        "type": "divider",
                    },
                    {
                        "type": "context",
                        "elements": [
                            {"type": "mrkdwn", "text": f"__{alert.timestamp}__"},
                        ],
                    },
                ],
            }
            
            # Add details if present
            if alert.details:
                details_text = json.dumps(alert.details, indent=2)
                payload["blocks"].insert(
                    4,
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Details*\n```\n{details_text}\n```",
                        },
                    },
                )
            
            response = requests.post(
                self.slack_webhook,
                json=payload,
                timeout=5,
            )
            response.raise_for_status()
            
            logger.info(f"Slack alert sent successfully for {alert.alert_type}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to send Slack alert: {e}")
            return False
    
    async def _send_email(self, alert: Alert) -> bool:
        """Send alert via email (stub - requires SMTP configuration)."""
        try:
            # TODO: Implement email sending via SMTP
            logger.info(f"Email alert prepared for {alert.alert_type} (SMTP not configured)")
            return True
        except Exception as e:
            logger.warning(f"Failed to send email alert: {e}")
            return False
    
    async def _send_to_webhook(self, alert: Alert, webhook_url: str) -> bool:
        """Send alert to generic webhook (for SIEM/SOAR integration)."""
        try:
            payload = alert.to_dict()
            
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            
            logger.info(f"Webhook alert sent to {webhook_url}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to send webhook alert to {webhook_url}: {e}")
            return False
    
    def is_duplicate(self, alert: Alert, time_window_seconds: int = 300) -> bool:
        """Check if alert is a duplicate (same type and org within time window)."""
        cutoff_time = (datetime.utcnow().timestamp() - time_window_seconds)
        
        for hist_alert in reversed(self.alert_history):
            alert_time = datetime.fromisoformat(hist_alert["timestamp"]).timestamp()
            
            if alert_time < cutoff_time:
                break
            
            if (hist_alert["alert_type"] == alert.alert_type and
                hist_alert["org_id"] == str(alert.org_id if alert.org_id else "")):
                return True
        
        return False


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get or create global alert manager."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


async def alert_indexing_failure(
    org_id: str,
    ioc_id: int,
    error_message: str,
    request_id: Optional[str] = None,
):
    """Alert when IOC indexing fails."""
    manager = get_alert_manager()
    
    alert = Alert(
        alert_type=AlertType.INDEXING_FAILURE,
        severity=AlertSeverity.HIGH,
        title=f"IOC indexing failed for IOC#{ioc_id}",
        description=f"Failed to index IOC to OpenSearch: {error_message}",
        org_id=org_id,
        request_id=request_id,
        details={
            "ioc_id": ioc_id,
            "error": str(error_message),
        },
    )
    
    if not manager.is_duplicate(alert):
        await manager.send_alert(alert)


async def alert_ingestion_failure(
    org_id: str,
    feed_source: str,
    error_message: str,
    request_id: Optional[str] = None,
):
    """Alert when feed ingestion fails."""
    manager = get_alert_manager()
    
    alert = Alert(
        alert_type=AlertType.INGESTION_FAILURE,
        severity=AlertSeverity.HIGH,
        title=f"Feed ingestion failed: {feed_source}",
        description=f"Failed to ingest from feed '{feed_source}': {error_message}",
        org_id=org_id,
        request_id=request_id,
        details={
            "feed_source": feed_source,
            "error": str(error_message),
        },
    )
    
    if not manager.is_duplicate(alert):
        await manager.send_alert(alert)


async def alert_search_failure(
    org_id: str,
    query: str,
    error_message: str,
    request_id: Optional[str] = None,
):
    """Alert when search query fails."""
    manager = get_alert_manager()
    
    alert = Alert(
        alert_type=AlertType.SEARCH_FAILURE,
        severity=AlertSeverity.MEDIUM,
        title="Search query failed",
        description=f"Failed to execute search: {error_message}",
        org_id=org_id,
        request_id=request_id,
        details={
            "query": query,
            "error": str(error_message),
        },
    )
    
    if not manager.is_duplicate(alert):
        await manager.send_alert(alert)


async def alert_quota_exceeded(
    org_id: str,
    quota_type: str,
    plan: str,
    request_id: Optional[str] = None,
):
    """Alert when org exceeds quota."""
    manager = get_alert_manager()
    
    alert = Alert(
        alert_type=AlertType.QUOTA_EXCEEDED,
        severity=AlertSeverity.MEDIUM,
        title=f"Quota exceeded: {quota_type}",
        description=f"Organization on {plan} plan exceeded {quota_type} quota",
        org_id=org_id,
        request_id=request_id,
        details={
            "quota_type": quota_type,
            "plan": plan,
        },
    )
    
    if not manager.is_duplicate(alert):
        await manager.send_alert(alert)


async def alert_entitlement_violation(
    org_id: str,
    user_id: int,
    feature: str,
    request_id: Optional[str] = None,
):
    """Alert when user tries to use feature they don't have entitlement for."""
    manager = get_alert_manager()
    
    alert = Alert(
        alert_type=AlertType.ENTITLEMENT_VIOLATION,
        severity=AlertSeverity.MEDIUM,
        title=f"Entitlement violation: {feature}",
        description=f"User #{user_id} tried to access feature '{feature}' without entitlement",
        org_id=org_id,
        request_id=request_id,
        details={
            "user_id": user_id,
            "feature": feature,
        },
    )
    
    if not manager.is_duplicate(alert):
        await manager.send_alert(alert)
