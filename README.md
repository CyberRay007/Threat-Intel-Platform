Threat Intelligence Platform

A modular threat intelligence and detection platform built with FastAPI, PostgreSQL, Redis, and Celery.

The platform ingests open threat intelligence feeds, normalizes indicators of compromise (IOCs), and correlates them with user scans and operational events to produce explainable risk scores and detection alerts.

The system demonstrates how modern threat intelligence platforms are built using asynchronous pipelines, external enrichment sources, and multi-signal scoring.

System Architecture

The platform consists of four primary subsystems.

Component	Responsibility
Scan Engine	Analyzes domains, URLs, and files
Intel Pipeline	Ingests and normalizes threat feeds
Detection Engine	Matches operational events against IOC database
Alerting System	Aggregates and manages detection alerts

Architecture overview:

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

sha256(observable_type + observable_value)
Threat Intelligence Sources

Integrated open intelligence feeds.

Feed	Data Type
PhishTank	Phishing URLs
OpenPhish	Phishing URLs
MalwareBazaar	Malware hashes
Abuse.ch URLHaus	Malware URLs
EmergingThreats	Malicious domains and IPs

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

git clone https://github.com/CyberRay007/Threat-Intel-Platform.git
cd Threat-Intel-Platform

Create virtual environment

Windows PowerShell

python -m venv .venv
.\.venv\Scripts\Activate.ps1

Install dependencies

pip install -r requirements.txt
Environment Configuration

Create .env file.

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
python init_db.py
python apply_schema_changes.py
Running the Platform

Start API server

uvicorn app.main:app --reload

Start Celery worker

celery -A app.tasks.celery_worker worker --loglevel=info

Run IOC feed ingestion manually

python feed_ingestion.py
API Documentation

Swagger

http://localhost:8000/docs

ReDoc

http://localhost:8000/redoc
Example Scan Response

Example domain scan result.

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
https://github.com/CyberRay007

License

MIT License