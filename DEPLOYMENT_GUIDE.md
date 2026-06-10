# PenteIA v4.0 - Deployment Guide

**Complete guide for deploying the web dashboard to production**

---

## 📋 Pre-Deployment Checklist

- [ ] All v4.0 modules installed and tested
- [ ] Flask and dependencies installed
- [ ] Templates directory created
- [ ] Static assets (CSS/JS) in place
- [ ] Security review completed
- [ ] API endpoints tested
- [ ] Database/logging configured (optional)

---

## 🚀 Quick Start (Development)

### 1. Installation

```bash
cd E:\cyber\PenteIA-V3.0

# Install dependencies
pip install flask flask-cors

# Or full stack:
pip install -r requirements.txt
```

### 2. Run Development Server

```bash
python app.py
```

### 3. Access Dashboard

Open browser to: **http://localhost:5000**

---

## 🔧 Production Deployment

### Option 1: Gunicorn (Linux/Mac)

```bash
# Install Gunicorn
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Or with supervisor for auto-restart
apt install supervisor
```

### Option 2: Waitress (Windows)

```bash
# Install Waitress
pip install waitress

# Run
waitress-serve --port=5000 app:app
```

### Option 3: Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
```

```bash
# Build and run
docker build -t penteia-v4 .
docker run -p 5000:5000 penteia-v4
```

---

## 🔐 Security Hardening

### 1. HTTPS/SSL

```python
# app.py - Add SSL context
if __name__ == '__main__':
    app.run(
        ssl_context=('cert.pem', 'key.pem'),
        host='0.0.0.0',
        port=5000
    )
```

Or use Nginx reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name penteia.example.com;

    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;

    location / {
        proxy_pass http://localhost:5000;
    }
}
```

### 2. Authentication

Add authentication layer:

```python
from flask_login import LoginManager, login_required

login_manager = LoginManager()
login_manager.init_app(app)

@app.route('/api/operations')
@login_required
def list_operations():
    # ...
```

### 3. Rate Limiting

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/operations/run-full', methods=['POST'])
@limiter.limit("5 per minute")
def run_full_operation():
    # ...
```

### 4. CORS Security

```python
CORS(app, resources={
    r"/api/*": {
        "origins": ["https://trusted-domain.com"],
        "methods": ["GET", "POST"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})
```

### 5. Environment Variables

```python
import os
from dotenv import load_dotenv

load_dotenv()

FLASK_ENV = os.getenv('FLASK_ENV', 'production')
SECRET_KEY = os.getenv('SECRET_KEY')
DEBUG = os.getenv('DEBUG', False)
```

Create `.env` file:

```
FLASK_ENV=production
SECRET_KEY=your-secret-key-here
DEBUG=False
DATABASE_URL=postgresql://user:pass@localhost/db
```

---

## 📊 Monitoring & Logging

### 1. Structured Logging

```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    file_handler = RotatingFileHandler('logs/penteia.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('PenteIA v4.0 startup')
```

### 2. Performance Monitoring

```python
import time
from functools import wraps

def timer_decorator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start = time.time()
        result = f(*args, **kwargs)
        elapsed = time.time() - start
        app.logger.info(f'{f.__name__} took {elapsed:.2f}s')
        return result
    return decorated_function

@app.route('/api/operations')
@timer_decorator
def list_operations():
    # ...
```

### 3. Error Tracking (Sentry)

```python
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

sentry_sdk.init(
    dsn="https://your-sentry-dsn@sentry.io/project",
    integrations=[FlaskIntegration()],
    traces_sample_rate=1.0
)
```

---

## 🗄️ Database Setup (Optional)

### SQLAlchemy Integration

```python
from flask_sqlalchemy import SQLAlchemy

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///penteia.db'
db = SQLAlchemy(app)

class Operation(db.Model):
    id = db.Column(db.String(16), primary_key=True)
    name = db.Column(db.String(255))
    status = db.Column(db.String(50))
    started_at = db.Column(db.DateTime)
    progress = db.Column(db.Integer)

db.create_all()
```

---

## 🚨 Reverse Proxy Setup

### Nginx Configuration

```nginx
upstream penteia {
    server localhost:5000;
    server localhost:5001;
    server localhost:5002;
}

server {
    listen 80;
    server_name penteia.example.com;

    client_max_body_size 100M;

    location / {
        proxy_pass http://penteia;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;

        # WebSocket support (if using)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### Apache2 Configuration

```apache
<VirtualHost *:80>
    ServerName penteia.example.com
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:5000/
    ProxyPassReverse / http://localhost:5000/
    
    <Location />
        Require all granted
    </Location>
</VirtualHost>
```

---

## 📈 Performance Tuning

### 1. Increase Workers (Gunicorn)

```bash
gunicorn -w 8 --worker-class sync -b 0.0.0.0:5000 app:app
```

### 2. Enable Caching

```python
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/api/modules/status')
@cache.cached(timeout=60)
def modules_status():
    # ...
```

### 3. Connection Pooling

```python
from sqlalchemy.pool import QueuePool

app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': QueuePool,
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
```

---

## 🧪 Testing Before Deployment

### Unit Tests

```python
# test_app.py
import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/api/health')
    assert response.status_code == 200
    assert 'version' in response.get_json()

def test_orchestrator_init(client):
    response = client.post('/api/orchestrator/init')
    assert response.status_code == 200
```

Run tests:

```bash
pytest test_app.py -v
```

### Load Testing

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:5000/api/health

# Using Locust
pip install locust

# Create locustfile.py
from locust import HttpUser, task, between

class DashboardUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def health_check(self):
        self.client.get("/api/health")

# Run
locust -f locustfile.py -u 100 -r 10
```

---

## 📝 Deployment Checklist

### Pre-Deployment
- [ ] All modules tested locally
- [ ] API endpoints functional
- [ ] Dashboard loads without errors
- [ ] Static files (CSS/JS) served correctly
- [ ] Environment variables configured
- [ ] Logs directory writable
- [ ] Security review completed

### During Deployment
- [ ] Backup existing data
- [ ] Update dependencies
- [ ] Run database migrations
- [ ] Test API endpoints
- [ ] Verify HTTPS working
- [ ] Check authentication
- [ ] Monitor logs for errors

### Post-Deployment
- [ ] Monitor performance
- [ ] Check error rates
- [ ] Verify backups working
- [ ] Update documentation
- [ ] Notify stakeholders
- [ ] Schedule monitoring

---

## 🔄 Continuous Integration/Deployment

### GitHub Actions Example

```yaml
name: Deploy PenteIA

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.11
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
      - name: Run tests
        run: |
          pytest test_app.py
      - name: Deploy to server
        run: |
          ssh user@server 'cd /var/www/penteia && git pull && systemctl restart penteia'
```

---

## 🎯 Production URLs

After deployment, access:

- **Dashboard:** https://penteia.example.com
- **API Base:** https://penteia.example.com/api
- **Health Check:** https://penteia.example.com/api/health
- **Documentation:** https://penteia.example.com/docs (if enabled)

---

## 🆘 Troubleshooting

### Port Already in Use

```bash
# Linux/Mac: Find and kill process
lsof -i :5000
kill -9 <PID>

# Windows: Use Resource Monitor
# Or change port in app.py
```

### Module Import Errors

```bash
# Ensure all modules in same directory
ls *.py | grep -E "(edr_|memory_|telemetry_|c2_|post_|bas_|automated_)"

# Check Python path
python -c "import sys; print('\n'.join(sys.path))"
```

### Database Lock

```bash
# Remove lock file if using SQLite
rm penteia.db-journal

# Or restart application
```

### Memory Issues

```bash
# Monitor memory usage
top -p $(pgrep -f "python app.py")

# Reduce worker count
gunicorn -w 2 app:app
```

---

## 📞 Support

For issues:
1. Check Flask terminal output
2. Review logs in `logs/penteia.log`
3. Check browser console (F12)
4. Review operation logs in dashboard

---

**Version:** 4.0  
**Last Updated:** 2026-06-10  
**Status:** ✅ Deployment Ready
