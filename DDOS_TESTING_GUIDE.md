# PenteIA v4.0 - DDoS Testing Module Guide

**Version:** 4.0  
**Module:** ddos_testing.py  
**Status:** ✅ Operational

---

## ⚠️ LEGAL DISCLAIMER

### AUTHORIZED USE ONLY

This module is provided **EXCLUSIVELY** for:

✅ **AUTHORIZED TESTING:**
- Testing your own infrastructure
- Penetration testing with written authorization
- Red team exercises (authorized)
- Internal security validation
- Resilience testing of YOUR systems

❌ **STRICTLY PROHIBITED:**
- Unauthorized DDoS attacks against any target
- Testing without explicit permission
- Targeting systems you don't own/operate
- Malicious intent
- Public distribution for harmful purposes
- Circumventing DDoS protections without consent

### LEGAL CONSEQUENCES

DDoS attacks against systems you do not own or have explicit permission to test are **CRIMINAL OFFENSES** in virtually all jurisdictions:

- **USA:** Computer Fraud and Abuse Act (CFAA) - up to 10 years prison
- **UK:** Computer Misuse Act 1990 - up to 10 years prison
- **EU:** Various cybercrime directives - 2-10 years prison
- **Brazil:** Lei 12.737/2012 - up to 4 years prison
- **Others:** Similar penalties worldwide

### Responsibility Clause

**The developer is NOT responsible for misuse of this module.** Users are solely responsible for:
- Ensuring authorization before any testing
- Complying with all applicable laws
- Obtaining written permission from system owners
- Understanding the legal implications

**You have been warned.**

---

## 🎯 Authorized Use Cases

### 1. Infrastructure Resilience Testing
```
Goal: Validate that your systems can handle DDoS attacks
Process:
  1. Document baseline performance
  2. Run controlled DDoS tests
  3. Monitor system response
  4. Document improvements
  5. Tune defenses
```

### 2. Defense Validation
```
Goal: Verify DDoS mitigation strategies work
Tests:
  - Does WAF block HTTP floods?
  - Does SYN proxy work?
  - Does rate limiting activate?
  - Does failover work?
```

### 3. Capacity Planning
```
Goal: Understand system limits
Measure:
  - Bandwidth saturation point
  - Connection limit exhaustion
  - CPU impact per request type
  - Memory utilization patterns
```

### 4. Red Team Exercise
```
Goal: Validate blue team readiness
Scenario:
  - Stage announced red team exercise
  - Brief security team
  - Execute DDoS test
  - Measure detection time
  - Evaluate response procedures
```

---

## 📋 Prerequisites

### Authorization Documentation
Before running ANY test, ensure you have:

```
□ Written authorization from system owner
□ Documented business justification
□ Defined scope (duration, intensity, systems)
□ Scheduled testing window
□ Notification to stakeholders
□ Emergency contact list
□ Rollback procedure documented
```

### Technical Requirements

1. **Network Access**
   - Direct network path to target (or proxy)
   - Sufficient bandwidth for test traffic
   - No intermediate firewalls blocking test traffic

2. **System Access**
   - Root/Admin access on testing machine
   - For SYN Flood: raw socket access
   - Monitoring tools running on target (optional but recommended)

3. **Monitoring Setup**
   - Network monitoring (tcpdump, Wireshark)
   - System monitoring (CPU, memory, I/O)
   - Application logging
   - Metrics collection (Prometheus, etc.)

---

## 🚀 Available Methods

### 1. HTTP Flood (Layer 7)
```
Mechanism: Send valid HTTP GET requests
Target: Web server/application
Detection: Harder (legitimate traffic)
Mitigation: Rate limiting, WAF rules
Effectiveness: Tests application capacity
```

**Configuration:**
- Target Port: 80 or 443
- Duration: 60-300 seconds
- RPS (Requests Per Second): 10-1000
- Recommended: Start low, increase gradually

**Example:**
```bash
Method: HTTP Flood
Target: 127.0.0.1:8080
Duration: 60 seconds
RPS: 100
Expected Impact: Web server resource exhaustion
```

---

### 2. SYN Flood (Layer 4)
```
Mechanism: Flood with TCP SYN packets
Target: Network stack
Detection: Easy (half-open connections)
Mitigation: SYN cookies, SYN proxy
Effectiveness: Tests network resilience
```

**Configuration:**
- Target Port: Any
- Duration: 30-120 seconds
- PPS (Packets Per Second): 100-10000
- Requires: Raw socket access (admin/root)

**Example:**
```bash
Method: SYN Flood
Target: 127.0.0.1:443
Duration: 60 seconds
PPS: 1000
Expected Impact: Network connection exhaustion
```

---

### 3. UDP Flood (Layer 4)
```
Mechanism: Flood with random UDP packets
Target: UDP services, bandwidth
Detection: Easy (anomalous traffic)
Mitigation: Ingress filtering, traffic shaping
Effectiveness: Tests bandwidth capacity
```

**Configuration:**
- Target Port: Any
- Duration: 60-300 seconds
- PPS: 100-10000
- Payload Size: 64-512 bytes

**Example:**
```bash
Method: UDP Flood
Target: 127.0.0.1:53
Duration: 120 seconds
PPS: 5000
Payload: 512 bytes
Expected Impact: Bandwidth saturation
```

---

### 4. Slowloris (Layer 7)
```
Mechanism: Keep connections open long-term
Target: Connection limits
Detection: Slow (looks like slow clients)
Mitigation: Connection timeout, resource limits
Effectiveness: Tests concurrent connection limits
```

**Configuration:**
- Target Port: 80 or 443
- Duration: 300-600 seconds
- Concurrent Connections: 10-1000
- Best for: Testing connection pool exhaustion

**Example:**
```bash
Method: Slowloris
Target: 127.0.0.1:80
Duration: 300 seconds
Connections: 100
Expected Impact: Connection pool exhaustion, timeout
```

---

### 5. DNS Amplification (Layer 3)
```
Mechanism: Amplify traffic via DNS servers
Target: Network bandwidth
Detection: Medium (traffic pattern)
Mitigation: DNS filtering, rate limiting
Effectiveness: Tests large-scale traffic absorption
```

**Configuration:**
- Target: DNS service
- Duration: 60-300 seconds
- PPS: 100-5000
- Amplification Factor: 50-100x

**Example:**
```bash
Method: DNS Amplification
Target: 127.0.0.1:53
Duration: 60 seconds
PPS: 1000
Expected Impact: DNS service saturation
```

---

## 🔐 Safety Mechanisms

### Built-in Protections

1. **Target Authorization Validation**
   ```python
   # Only allows testing on:
   - 127.0.0.1 (localhost)
   - 192.168.x.x (private)
   - 10.x.x.x (private)
   - 172.16-31.x.x (private)
   ```

2. **Authorization Flag**
   ```python
   config = DDoSConfig(
       target_host='127.0.0.1',
       authorized=True  # Must be explicit
   )
   ```

3. **Logging & Audit Trail**
   - All tests logged with timestamp
   - Target, method, duration recorded
   - Results stored for review
   - Integration with operation logs

4. **Duration Limits**
   - Recommended max: 300 seconds
   - Configurable per test
   - Emergency stop available

---

## 📊 Running Tests

### Via Dashboard

1. Navigate to http://localhost:5000/ddos
2. Configure test parameters:
   - Target Host (localhost or private IP)
   - Target Port
   - Attack Method
   - Duration
   - Packets Per Second
3. Click "Start Test"
4. Monitor active tests
5. Review results

### Via API

```bash
# Start HTTP Flood
curl -X POST http://localhost:5000/api/ddos/start \
  -H "Content-Type: application/json" \
  -d '{
    "target_host": "127.0.0.1",
    "target_port": 80,
    "method": "http_flood",
    "duration": 60,
    "pps": 100
  }'

# Get active tests
curl http://localhost:5000/api/ddos/active

# Stop test
curl -X POST http://localhost:5000/api/ddos/stop/http_flood_1234567890_5678

# Get results
curl http://localhost:5000/api/ddos/results
```

### Via Python

```python
from ddos_testing import DDoSTestingEngine, DDoSConfig, DDoSMethod

engine = DDoSTestingEngine()

# Validate target is authorized
if not engine.validate_authorization('127.0.0.1'):
    print("Target not authorized!")
    exit()

# Configure test
config = DDoSConfig(
    target_host='127.0.0.1',
    target_port=80,
    method=DDoSMethod.HTTP_FLOOD,
    duration_seconds=60,
    packets_per_second=100,
    authorized=True,
    test_name="HTTP Flood Test"
)

# Start test
result = engine.start_http_flood(config)
print(f"Test started: {result['test_id']}")

# Monitor
while True:
    status = engine.get_test_status(result['test_id'])
    if status['status'] == 'completed':
        break
    time.sleep(5)

# Review results
results = engine.get_test_results()
for r in results:
    print(f"{r['method']}: {r['packets_sent']} packets sent")
```

---

## 📈 Interpreting Results

### Key Metrics

| Metric | Meaning | Good Range |
|--------|---------|-----------|
| **Packets Sent** | Total packets transmitted | Depends on duration |
| **Bytes Sent** | Total data transmitted | Depends on payload size |
| **Duration** | Actual test time | ~= requested duration |
| **PPS** | Packets per second actual | ~= configured PPS |
| **Success Rate** | % packets delivered | 95-100% |

### Example Results

```json
{
  "test_id": "http_flood_1234567890_5678",
  "method": "HTTP Flood",
  "target": "127.0.0.1:80",
  "duration": 60,
  "packets_sent": 6000,
  "bytes_sent": 2400000,
  "start_time": "2026-06-10T12:00:00",
  "end_time": "2026-06-10T12:01:00",
  "success": true
}
```

### System Impact Analysis

**During Test, Monitor:**
1. CPU usage (should be 80%+)
2. Memory usage (check for leaks)
3. Network saturation (% of capacity)
4. Request latency (should increase)
5. Error rates (should increase)
6. Cache hit rates (should decrease)

**After Test, Analyze:**
1. Recovery time (how long to baseline)
2. Graceful degradation (does it fail closed?)
3. Log volume (can logging handle load?)
4. Database impact (are queries still responsive?)

---

## 🛑 Emergency Procedures

### If Test Goes Wrong

1. **Immediate Stop**
   ```
   Click "Stop" button in dashboard
   Or: curl -X POST /api/ddos/stop/<test_id>
   ```

2. **Kill Process**
   ```bash
   ps aux | grep ddos_testing
   kill -9 <PID>
   ```

3. **Network Isolation**
   - Disconnect test machine from network
   - Kill Flask process: `pkill -f "python app.py"`
   - Restart from isolated state

4. **Rollback Production**
   - Failover to backup systems
   - Restore from snapshot
   - Alert stakeholders

---

## 📋 Test Documentation Template

```markdown
# DDoS Test Report

## Authorization
- Date Authorized: 2026-06-10
- Authorized By: Security Team Lead
- Scope: Internal HTTP server
- Duration Approved: 60 seconds

## Test Configuration
- Method: HTTP Flood
- Target: 127.0.0.1:8080
- Duration: 60 seconds
- RPS: 100
- Expected Behavior: Server should handle load

## Baseline Metrics
- Normal RPS: 50
- Normal CPU: 10%
- Normal Memory: 500MB
- Normal Response Time: 50ms

## Test Results
- Packets Sent: 6000
- Bytes Sent: 2.4MB
- Peak CPU: 95%
- Peak Memory: 1.2GB
- Peak Latency: 500ms

## Analysis
- Server remained operational
- Graceful degradation observed
- Rate limiting activated correctly
- Recovery time: 30 seconds

## Recommendations
1. Increase worker threads to 64
2. Implement connection pooling
3. Add horizontal scaling capability
```

---

## 🎓 Best Practices

### Before Testing
- [ ] Get written authorization
- [ ] Notify operations team
- [ ] Set clear test objectives
- [ ] Document baseline metrics
- [ ] Prepare monitoring tools
- [ ] Have rollback plan
- [ ] Test in isolated environment first

### During Testing
- [ ] Monitor all metrics actively
- [ ] Have hand on kill switch
- [ ] Watch for unexpected behavior
- [ ] Document observations
- [ ] Be ready to stop
- [ ] Observe system behavior

### After Testing
- [ ] Verify system recovered
- [ ] Collect all logs/metrics
- [ ] Document results
- [ ] Analyze impact
- [ ] Update procedures
- [ ] Share findings

---

## 🔗 Integration with PenteIA

The DDoS module integrates with:

1. **Orchestrator**
   - Can be called as part of full assessment
   - Coordinates with other modules
   - Participates in BAS workflow

2. **Logging System**
   - All tests logged in operation_logs
   - Results stored for reporting
   - Integrated with dashboard timeline

3. **Reporting**
   - DDoS test results included in reports
   - Findings exported as JSON
   - Can generate PDF/HTML reports

---

## 📞 Support & Troubleshooting

### Common Issues

**"Target not authorized"**
- Ensure target is localhost or private IP
- Check IP range: 127.x, 192.168.x, 10.x, 172.16-31.x

**"Permission denied (raw socket)"**
- SYN Flood requires root/admin
- Run with elevated privileges
- Or use HTTP Flood instead

**"Connection refused"**
- Verify target service is running
- Check firewall rules
- Verify port number

**"Test hangs"**
- Check network connectivity
- Verify target not blocking
- Stop test and restart

---

## 📚 Further Reading

- [OWASP DDoS Prevention](https://owasp.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [RFC 4987 - TCP SYN Flooding Attacks](https://tools.ietf.org/html/rfc4987)

---

**Remember: With great power comes great responsibility.**

**Only test systems you own or have explicit permission to test.**

---

**Version:** 4.0  
**Last Updated:** 2026-06-10  
**Status:** ✅ Ready for Authorized Testing
