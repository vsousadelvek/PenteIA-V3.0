# PenteIA v4.0 - Web Dashboard & Frontend Guide

**Version:** 4.0  
**Framework:** Flask + Bootstrap 5  
**Status:** ✅ Production Ready

---

## 📋 Overview

Professional web dashboard for PenteIA v4.0 with:
- **Real-time monitoring** of operations
- **Interactive C2 beacon management**
- **BAS playbook execution**
- **Automated report generation**
- **Evasion technique testing**
- **RESTful API** for all modules

---

## 🚀 Quick Start

### Installation

```bash
cd E:\cyber\PenteIA-V3.0

# Install Flask and dependencies
pip install flask flask-cors

# Or install all:
pip install -r requirements.txt
```

### Running the Dashboard

```bash
python app.py
```

Access at: **http://localhost:5000**

---

## 📁 Frontend Structure

```
E:\cyber\PenteIA-V3.0\
├── app.py                      # Flask backend & API
├── templates/                  # HTML templates
│   ├── base.html              # Base layout
│   ├── index.html             # Dashboard home
│   ├── modules.html           # Module management
│   ├── c2.html                # C2 beacon control
│   ├── bas.html               # BAS playbooks
│   ├── operations.html        # Operations monitor
│   ├── reporting.html         # Report generation
│   └── evasion.html           # Evasion testing
├── static/                    # Static assets
│   ├── css/
│   │   └── style.css          # Custom dark theme CSS
│   └── js/
│       └── main.js            # Shared JavaScript utilities
└── FRONTEND_GUIDE.md          # This file
```

---

## 🎨 Pages Overview

### 1. Dashboard (`/`)
**Main interface with:**
- System health status
- Module activation count
- Running operations counter
- Total findings display
- Quick action buttons
- Operation charts (doughnut & bar)
- Recent operations list
- Real-time operation logs

**Actions:**
- Initialize Orchestrator
- Run Full Operation
- Run BAS Assessment
- Check Sandbox
- Auto-refresh every 5 seconds

### 2. Modules (`/modules`)
**Module management interface:**
- Display all 7 modules
- Module capabilities
- Configuration viewer
- Status indicators

**Modules shown:**
- EDR Evasion
- Memory Evasion
- Telemetry Bypass
- C2 Framework
- Post-Exploitation
- BAS Engine
- Automated Reporting

### 3. C2 Beacon (`/c2`)
**Beacon session management:**
- Create new beacons with different profiles
- List active beacons
- Execute commands remotely
- Exfiltrate data
- Session monitoring

**Profiles:**
- Azure Telemetry
- AWS SDK
- Office 365
- DNS over HTTPS

### 4. BAS (`/bas`)
**MITRE ATT&CK playbook execution:**
- Lateral Movement playbook
- Credential Harvesting playbook
- Persistence playbook
- Defense Evasion playbook
- Full Assessment (all playbooks)
- Real-time results

### 5. Operations (`/operations`)
**Operation monitoring:**
- Table of all operations
- Status tracking
- Progress bars
- Finding counts
- Operation details view
- Auto-refresh

### 6. Reporting (`/reporting`)
**Report generation:**
- Configure report parameters
- Generate reports
- Export formats (HTML, PDF, DOCX)
- Report history
- Finding summary

### 7. Evasion (`/evasion`)
**Evasion technique testing:**
- Sandbox detection
- Sleep obfuscation testing
- Test result tracking
- Environment safety check

---

## 🔌 API Endpoints

### Health & Status
```
GET  /api/health                      # Health check
GET  /api/status                      # System status
GET  /api/analytics/dashboard         # Dashboard analytics
```

### Orchestrator
```
POST /api/orchestrator/init           # Initialize all modules
GET  /api/modules/status              # List all modules
GET  /api/modules/config/<name>       # Get module config
```

### Operations
```
GET  /api/operations                  # List all operations
POST /api/operations/run-full         # Run full operation
GET  /api/operations/<id>             # Get operation details
```

### C2 Framework
```
GET  /api/c2/beacons                  # List active beacons
POST /api/c2/beacon/create            # Create new beacon
POST /api/c2/beacon/<id>/command      # Execute command on beacon
```

### BAS Engine
```
GET  /api/bas/playbooks               # List playbooks
POST /api/bas/run-playbook            # Run specific playbook
POST /api/bas/full-assessment         # Run full assessment
```

### Reporting
```
POST /api/reporting/generate          # Generate report
```

### Evasion
```
POST /api/evasion/sandbox-check       # Check sandbox
POST /api/evasion/sleep-obfuscate     # Test sleep obfuscation
```

### Logging
```
GET  /api/logs                        # Get operation logs
```

---

## 🎯 Usage Examples

### Example 1: Initialize and Run Operation

```javascript
// 1. Initialize orchestrator
fetch('/api/orchestrator/init', { method: 'POST' })
    .then(r => r.json())
    .then(data => console.log('Initialized:', data));

// 2. Run full operation
fetch('/api/operations/run-full', { method: 'POST' })
    .then(r => r.json())
    .then(data => console.log('Operation:', data.operation_id));

// 3. Monitor progress
setInterval(() => {
    fetch(`/api/operations/${operationId}`)
        .then(r => r.json())
        .then(data => console.log('Progress:', data.progress + '%'));
}, 2000);
```

### Example 2: Create Beacon

```javascript
fetch('/api/c2/beacon/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: 'azure' })
})
.then(r => r.json())
.then(data => console.log('Beacon:', data.beacon_id));
```

### Example 3: Run Playbook

```javascript
fetch('/api/bas/run-playbook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ playbook: 'lateral_movement' })
})
.then(r => r.json())
.then(data => console.log('Assessment:', data.operation_id));
```

---

## 🎨 Styling & Theme

### Colors Used
- **Primary Dark:** `#1a1a1a` (backgrounds)
- **Secondary Dark:** `#2d2d2d` (cards)
- **Accent Red:** `#dc3545` (danger/alerts)
- **Accent Yellow:** `#ffc107` (warning)
- **Accent Blue:** `#17a2b8` (info)
- **Accent Green:** `#28a745` (success)

### Dark Theme
- All pages use dark theme optimized for hacking/security context
- Custom scrollbars
- High contrast text
- Responsive design for mobile

---

## 🔄 Real-Time Updates

### Auto-Refresh Intervals
- Status: 5 seconds
- Operations: 5 seconds
- Logs: 3 seconds
- Beacons: 5 seconds

### Manual Refresh Buttons
All pages include manual refresh buttons for:
- Operations list
- Beacons list
- Operation logs
- Module status

---

## 📊 Charts & Visualizations

### Dashboard Charts
1. **Operations Status (Doughnut)**
   - Running (yellow)
   - Completed (green)
   - Failed (red)

2. **Findings by Severity (Bar)**
   - Critical (red)
   - High (orange)
   - Medium (orange)
   - Low (blue)
   - Info (gray)

### Real-Time Updates
Charts update every 5 seconds with latest data.

---

## 💾 Data Management

### Operation Logs
- Captured automatically
- Stored in memory (session)
- Clearable from dashboard
- Max 100 entries shown
- Timestamps included

### Generated Reports
- Stored in memory
- Can be exported as HTML, PDF, DOCX
- Include findings summary
- Include remediation recommendations

### Session Beacons
- Managed in C2Controller
- Active sessions displayed
- Commands tracked
- Data exfiltration logged

---

## 🔐 Security

### CORS Enabled
- Cross-Origin Requests allowed for development
- In production, restrict to trusted origins

### Session Management
- Flask session secret key generated
- Cookie-based session tracking
- CSRF protection available (can be enabled)

### Input Validation
- All API endpoints validate input
- JSON payloads checked
- Parameters sanitized

---

## 🐛 Debugging

### Enable Debug Mode
```python
# In app.py, change to:
app.run(debug=True)
```

### Check Logs
- Browser console (F12)
- Flask terminal output
- Operation logs page

### Common Issues

**"Module not found"**
- Ensure all v4.0 modules are in same directory
- Check imports in app.py

**"API returns 500"**
- Check Flask terminal for error
- Verify module initialization
- Check operation_logs for failures

**"Dashboard not loading"**
- Verify Flask is running on port 5000
- Check browser console for errors
- Clear browser cache

---

## 📱 Mobile Support

Dashboard is responsive and works on:
- ✅ Desktop (1920x1080+)
- ✅ Tablet (768px+)
- ✅ Mobile (320px+)

All buttons and forms are mobile-friendly.

---

## 🔗 Integration

### With v3.0 Scanner
```python
from scanner import PenteiaScan
from app import app

# Run scanner in Flask thread
scan_results = PenteiaScan(config='config.json').scan(urls)
```

### With External Tools
- Export findings as JSON
- Send to SIEM via API
- Download reports for distribution

---

## 📈 Performance

### Optimizations
- Charts rendered client-side (no server load)
- Auto-refresh intervals tuned
- Efficient API calls
- Minimal DOM manipulation

### Load Testing
- Tested with 100+ concurrent operations
- 5-second refresh interval stable
- Memory usage stable

---

## 🆘 Support

### Resources
1. **Browser Console** - JavaScript errors
2. **Flask Terminal** - Python errors
3. **Operation Logs** - Execution logs
4. **API Responses** - Data validation

### Testing Endpoints
```bash
# Test health
curl http://localhost:5000/api/health

# Test status
curl http://localhost:5000/api/status

# Initialize
curl -X POST http://localhost:5000/api/orchestrator/init
```

---

## 📚 Next Steps

1. **Deploy to Production**
   - Use production WSGI server (Gunicorn, etc.)
   - Enable HTTPS
   - Configure proper logging

2. **Extend Dashboard**
   - Add more visualizations
   - Custom playbook builder
   - Real-time metric streaming

3. **Integrate External Tools**
   - Slack notifications
   - Email reporting
   - Webhook integrations

---

## 📄 License & Usage

**For authorized testing only in controlled environments.**

All pages include security disclaimers.

---

**Version:** 4.0  
**Last Updated:** 2026-06-10  
**Status:** ✅ Production Ready
