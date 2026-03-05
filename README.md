# Threat Intel Platform

A comprehensive threat intelligence platform built with **FastAPI** and **PostgreSQL** for analyzing domains, URLs, and IOCs with risk scoring, behavioral analysis, and VirusTotal integration.

## 📋 Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Architecture](#architecture)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## ✨ Features

- **Intelligence Gathering**: Scan domains, URLs, and IOCs for threat analysis
- **Risk Scoring**: Dynamic, explainable scoring algorithm based on multiple factors
- **Behavioral Analysis**: Detect homograph attacks, entropy analysis, and similarity matching
- **VirusTotal Integration**: Real-time malware detection and threat intelligence
- **Async Processing**: Background task queue using Celery for scalable processing
- **JWT Authentication**: Secure token-based API authentication
- **Database Migrations**: Alembic-based schema management
- **API Rate Limiting**: Protected endpoints with configurable rate limits

## 🛠 Tech Stack

- **Backend**: FastAPI (Python 3.8+)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery for async processing
- **Authentication**: JWT (PyJWT)
- **Password Hashing**: Argon2
- **API**: RESTful API with automatic Swagger documentation
- **Database Migrations**: Alembic

## 📦 Prerequisites

Before you begin, ensure you have the following installed:

- **Python 3.8+**
- **PostgreSQL 12+** (or another supported database)
- **pip** package manager
- **Git** version control

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/threat-intel-platform.git
cd threat-intel-platform
```

### 2. Create Virtual Environment

```powershell
# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# macOS/Linux
python -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Copy the example environment file and update with your actual values:

```bash
copy .env.example .env
```

Edit `.env` with your configuration:

```ini
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/threat_intel_db

# VirusTotal API (get from https://www.virustotal.com/gui/home/upload)
VT_API_KEY=your_api_key_here

# JWT Security
SECRET_KEY=your-secret-key-min-32-characters-long
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Application
DEBUG=false
LOG_LEVEL=info
```

**⚠️ Important**: Never commit `.env` file. Use `.env.example` as a template.

### 5. Initialize Database

```powershell
# Create database tables
.venv\Scripts\python.exe init_db.py

# Apply migrations (optional if using alembic)
.venv\Scripts\python.exe apply_schema_changes.py
```

## ▶️ Running the Application

### Development Server

```powershell
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --log-level debug
```

Server will start at: `http://localhost:8000`

### API Documentation

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Background Tasks (Celery Worker)

```powershell
celery -A app.tasks.celery_worker worker --loglevel=info
```

## 🏗 Architecture

```
app/
├── api/               # API endpoints
│   ├── routes_auth.py         # Authentication routes
│   ├── routes_dashboard.py    # Dashboard endpoints
│   └── routes_scan.py         # Scan operations
├── core/              # Core utilities
│   ├── jwt.py                 # JWT token handling
│   ├── security.py            # Security utilities
│   └── logging.py             # Logging configuration
├── database/          # Database layer
│   ├── models.py              # SQLAlchemy models
│   └── session.py             # Database session management
├── schemas/           # Pydantic validation schemas
│   ├── auth_schema.py
│   └── scan_schema.py
├── services/          # Business logic
│   ├── behavior_engine.py     # Behavioral analysis
│   ├── domain_engine.py       # Domain intelligence
│   ├── exploit_engine.py      # Exploit detection
│   ├── ioc_service.py         # IOC processing
│   ├── risk_engine.py         # Risk scoring
│   ├── vt_service.py          # VirusTotal integration
│   └── orchestrator.py        # Orchestrate services
├── tasks/             # Async tasks
│   ├── celery_worker.py       # Celery configuration
│   └── scan_tasks.py          # Scan task definitions
├── utils/             # Helper utilities
│   ├── entropy.py             # Entropy calculation
│   ├── homograph.py           # Homograph detection
│   └── similarity.py          # String similarity
└── main.py            # Application entry point
```

## 🔌 API Endpoints

### Authentication

- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - Authenticate user

### Scanning

- `POST /api/scan/domain` - Scan and analyze a domain
- `POST /api/scan/url` - Scan and analyze a URL
- `POST /api/scan/ioc` - Analyze indicators of compromise
- `GET /api/scan/{scan_id}` - Retrieve scan results

### Dashboard

- `GET /api/dashboard/summary` - Get platform summary
- `GET /api/dashboard/stats` - Get threat statistics

## 🔒 Security Considerations

### Do NOT Commit

- ❌ `.env` file with credentials
- ❌ API keys or secrets
- ❌ Database passwords
- ❌ Virtual environment (`venv/`, `.venv/`)
- ❌ Session tokens or temporary auth files

### Best Practices

✅ Use `.env.example` as template with placeholder values  
✅ Use strong `SECRET_KEY` for JWT (minimum 32 characters)  
✅ Enable `DEBUG=false` in production  
✅ Use environment-specific `.env` files for different deployments  
✅ Rotate API keys regularly  
✅ Use HTTPS for all production endpoints  
✅ Implement rate limiting on sensitive endpoints  

## 📝 Notes

- The service performs metadata analysis only (no content fetching)
- Scoring algorithm is deterministic and explainable; easily replaced with ML models
- Respect VirusTotal API rate limits: [VirusTotal Free API](https://www.virustotal.com/gui/home/upload)
- Database models support `scan_results` table and `file_scans` table for comprehensive logging

## 🤝 Contributing

1. Create a feature branch (`git checkout -b feature/AmazingFeature`)
2. Commit your changes (`git commit -m 'Add AmazingFeature'`)
3. Push to the branch (`git push origin feature/AmazingFeature`)
4. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

**Last Updated**: March 2026  
**Maintainer**: Raymond Favour
