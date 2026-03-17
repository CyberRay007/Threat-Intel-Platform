Threat Intelligence Platform
A modular threat intelligence and detection platform built with FastAPI, PostgreSQL, Redis, and Celery.
The platform ingests open threat intelligence feeds, normalizes indicators of compromise (IOCs), and correlates them with user scans and operational events to produce explainable risk scores and detection alerts.
The system demonstrates how modern threat intelligence platforms are built using asynchronous pipelines, external enrichment sources, and multi-signal scoring.
System Architecture
The platform consists of four primary subsystems.
Component
Responsibility
Scan Engine
Analyzes domains, URLs, and files
Intel Pipeline
Ingests and normalizes threat feeds
Detection Engine
Matches operational events against IOC database
Alerting System
Aggregates and manages detection alerts
Architecture overview:
Plain text
Copy code
+-------------------+
                   |  Threat Feeds     |
                   | (URLHaus, OTX...) |
                   +---------+---------+
                             |
                             v
                   +-------------------+
                   | IOC Normalization |
                   |  & Storage        |
                   +---------+---------+
                             |
                             v
        +---------------------------+
        |        IOC Database       |
        +-------------+-------------+
                      |
                      v
      +------------------------------+
      |     Detection Engine         |
      | (Celery async processing)    |
      +-------------+----------------+
                    |
                    v
           +-------------------+
           |       Alerts      |
           +-------------------+

User scans feed into the same intelligence layer:

User Scan → Scan Engine → Intel Correlation → Risk Score
Core Capabilities
Threat Analysis
• Domain and URL scanning
• File hash intelligence lookup
• VirusTotal enrichment
• Structural phishing detection signals
Threat Intelligence
• Multi-source IOC ingestion
• IOC normalization and deduplication
• Graph relationships between indicators and campaigns
Detection Pipeline
• Event ingestion API
• Asynchronous detection workers
• IOC matching against events
• Alert aggregation and fingerprinting
Risk Intelligence
• Multi-signal scoring model
• Historical domain behavior signals
• Feed intelligence correlation
Roadmap Implementation
The repository follows a staged development roadmap.
Week 1
Authentication and user management using JWT.
Week 2
Scan engine with domain and URL analysis and VirusTotal integration.
Week 3
Structural intelligence signals and IOC correlation.
Week 4
Large scale ingestion of open threat intelligence feeds.
Week 5
Detection engine with event ingestion, IOC matching, and alert aggregation.
Week 6
Multi-signal risk scoring using historical behavior and feed intelligence.
Detection Workflow
The detection pipeline operates asynchronously.
Plain text
Copy code
Client Event
     |
     v
POST /api/detection/events
     |
     v
Event stored in database
     |
     v
Celery worker processes event
     |
     v
IOC matching against intelligence database
     |
     v
Alert created or aggregated
Alert aggregation prevents duplicate alerts by fingerprinting observables.
Example fingerprint:
Copy code

sha256(observable_type + observable_value)
Threat Intelligence Sources
Integrated open intelligence feeds.
Feed
Data Type
PhishTank
Phishing URLs
OpenPhish
Phishing URLs
MalwareBazaar
Malware hashes
Abuse.ch URLHaus
Malware URLs
EmergingThreats
Malicious domains and IPs
Optional feed
AlienVault OTX (requires API key)
External enrichment
VirusTotal
Technology Stack
Backend
Python
FastAPI
SQLAlchemy (Async ORM)
Data Layer
PostgreSQL
Async Processing
Celery
Redis
Security
JWT Authentication
Data Validation
Pydantic
Project Structure
Copy code

app
 ├── api
 │    ├── routes_auth.py
 │    ├── routes_dashboard.py
 │    ├── routes_detection.py
 │    ├── routes_intel.py
 │    └── routes_scan.py
 │
 ├── core
 ├── database
 ├── schemas
 ├── services
 ├── tasks
 └── utils

docker
migrations

init_db.py
apply_schema_changes.py
feed_ingestion.py
Key directories
api
Contains REST API routes.
services
Core business logic including threat analysis and intelligence processing.
tasks
Celery workers for asynchronous jobs.
schemas
Pydantic request and response models.
Setup
Clone the repository
Copy code

git clone https://github.com/CyberRay007/Threat-Intel-Platform.git
cd Threat-Intel-Platform
Create virtual environment
Windows PowerShell
Copy code

python -m venv .venv
.\.venv\Scripts\Activate.ps1
Install dependencies
Copy code

pip install -r requirements.txt
Environment Configuration
Create .env file.
Copy code

DATABASE_URL=postgresql://threat_user:password@localhost:5432/threat_intel_db

VT_API_KEY=your_virustotal_key
OTX_API_KEY=your_otx_key

SECRET_KEY=replace-with-long-random-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

DEBUG=false
LOG_LEVEL=info

CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
Database Initialization
Copy code

python init_db.py
python apply_schema_changes.py
Running the Platform
Start API server
Copy code

uvicorn app.main:app --reload
Start Celery worker
Copy code

celery -A app.tasks.celery_worker worker --loglevel=info
Run IOC feed ingestion manually
Copy code

python feed_ingestion.py
API Documentation
Swagger
Copy code

http://localhost:8000/docs
ReDoc
Copy code

http://localhost:8000/redoc
Example Scan Response
Example domain scan result.
JSON
Copy code
{
  "domain": "example-phish.com",
  "risk_score": 82,
  "signals": {
    "structural_score": 25,
    "ioc_score": 20,
    "vt_score": 15,
    "feed_intel_score": 12,
    "historical_score": 10
  },
  "verdict": "malicious"
}
Security Best Practices
Never commit .env files.
Rotate exposed API keys immediately.
Use strong secret keys for JWT signing.
Disable debug mode outside development.
Future Improvements
Planned enhancements include:
• threat actor attribution
• campaign clustering
• graph-based IOC relationships
• streaming detection pipeline
• machine learning risk scoring
Maintainer
Raymond Favour
GitHub
https://github.com/CyberRay007⁠�
License
MIT License

Week 6 Backend Completion Report (2026-03-16)
This section captures the final Week 6 backend verification before Week 7 frontend implementation.

Completed backend capabilities
• IOC relationship graph endpoint implemented: GET /api/intel/ioc/{ioc_id}/relationships
• Behavioral detection rules engine implemented and wired into event processing
• Security operations overview endpoint implemented: GET /api/dashboard/security-overview
• Schema patch hardening completed for legacy databases where alerts.event_id may not exist

Database and ingestion verification
• apply_schema_changes.py completed successfully after legacy column guards were added
• IOC ingestion clean pass completed
• IOC totals before/after ingestion: 42,389 -> 42,500 (delta +111)
• Per-source delta:
     - abusech_urlhaus: +106
     - alienvault_otx: 0
     - emergingthreats: +5
     - malwarebazaar: 0
     - openphish: 0
     - phishtank: 0

IOC graph verification
• ioc_graph_relationships row count: 13,761
• Endpoint validation on IOC id 18458 returned populated results
• Live API check result: total_relationships=500, list_count=500

Threat test verification
• Real phishing IOC URL flow executed through authenticated API scan path
• EICAR safe malware simulation file scan completed with high-risk result
• file_scans verification sample: status=completed, vt_score=67, risk_score=100

Week 7 readiness
Backend Week 6 requirements are validated and committed; frontend Week 7 implementation can start from this checkpoint.

Production Readiness Checkpoint (2026-03-17)
This checkpoint reflects the current architecture status after validating backend and deployment modules.

Current readiness summary
Implemented strongly
• Core detection/intelligence prototype mechanics
• Versioned API routing (/api/v1)
• Organization-linked data model with org-scoped queries in critical paths
• JWT + API key authentication and baseline RBAC permission checks
• Dockerized local stack (API, worker, Redis, Postgres, nginx)

Partial but promising
• Feed ingestion operations and async replay reliability foundations
• Structured JSON logging and request latency logging
• Analyst-facing UI and investigation flows
• Feed export endpoints (JSON/CSV)

High-risk gaps for commercial SaaS
• Full tenant-isolation test coverage and hard guarantees across all code paths
• Observability stack (metrics, dashboards, alerting)
• Integration contracts (SIEM/SOAR connectors, STIX/TAXII support)
• Billing/subscription and usage metering
• Compliance governance (retention, audit posture, privacy controls)

Priority order to become a production TIP service
1. Harden multi-tenant isolation end-to-end
     - Validate org filters on every read/write path
     - Add cross-tenant negative tests for auth/intel/detection/export APIs
2. Productize access control and API surface
     - Standardize and document /api/v1 contracts
     - Expand API key lifecycle controls (issue/revoke/rotate)
     - Move rate limiting from in-memory to Redis-backed controls
3. Implement observability and reliability controls
     - Introduce metrics for ingest freshness, queue lag, latency, and error rates
     - Add feed failure and backlog growth alerting
4. Define integration and export standards
     - Add first SIEM connector (for example Splunk or Elastic)
     - Add STIX/TAXII export support
5. Add SaaS and governance foundations
     - Plans, quotas, usage metering, and billing hooks
     - Retention policies, data governance controls, and compliance runbooks

Immediate next sprint recommendation (2 weeks)
• Tenant isolation test matrix and remediation
• Redis-backed per-org/per-key rate limiting
• Feed health persistence (last_success, last_failure, failure_count, freshness)
• Metrics endpoint and baseline operational dashboard
• API key lifecycle endpoints with audit events