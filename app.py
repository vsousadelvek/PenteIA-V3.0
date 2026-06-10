#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PenteIA v4.0 - Web Dashboard & API Backend
Frontend profissional com Flask + WebSocket para operações em tempo real
"""

import json
import os
from datetime import datetime
from threading import Thread
import secrets

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS

# Import dos módulos PenteIA v4.0
from penteia_v4_orchestrator import PenteIAv4Orchestrator
from c2_framework import C2Controller
from bas_engine import BASPlaybookRunner, Playbook
from automated_reporting import JinjaReportGenerator, ReportExporter
from memory_evasion import SleepObfuscator
from edr_evasion_core import SandboxDetector
from ddos_testing import DDoSTestingEngine, DDoSConfig, DDoSMethod


# ============================================================================
# Flask App Configuration
# ============================================================================

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
CORS(app)

# Global state
orchestrator = None
active_operations = {}
operation_logs = []


# ============================================================================
# API Routes - Health & Status
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': 'PenteIA v4.0',
        'timestamp': datetime.now().isoformat(),
        'frontend': 'active'
    })


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    global orchestrator

    if not orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 400

    status = orchestrator.get_status()
    status['active_operations'] = len(active_operations)
    status['operation_logs'] = len(operation_logs)

    return jsonify(status)


# ============================================================================
# API Routes - Orchestrator & Modules
# ============================================================================

@app.route('/api/orchestrator/init', methods=['POST'])
def init_orchestrator():
    """Initialize orchestrator and all modules"""
    global orchestrator

    try:
        orchestrator = PenteIAv4Orchestrator()
        modules_status = orchestrator.initialize_all_modules()

        log_operation('INIT', 'Orchestrator initialized with all modules')

        return jsonify({
            'status': 'success',
            'message': 'Orchestrator initialized',
            'modules': {k: v['status'] for k, v in modules_status.items()},
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/modules/status', methods=['GET'])
def modules_status():
    """Get status of all modules"""
    global orchestrator

    if not orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 400

    modules = orchestrator.modules
    status = {}

    for module_name, module_data in modules.items():
        if isinstance(module_data, dict):
            status[module_name] = {
                'name': module_name,
                'status': 'ready',
                'config': module_data.get('config', {})
            }
        else:
            status[module_name] = {
                'name': module_name,
                'status': 'ready',
            }

    return jsonify({
        'modules': status,
        'total': len(status),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/modules/config/<module_name>', methods=['GET'])
def get_module_config(module_name):
    """Get configuration of specific module"""
    global orchestrator

    if not orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 400

    if module_name not in orchestrator.modules:
        return jsonify({'error': f'Module not found: {module_name}'}), 404

    module = orchestrator.modules[module_name]

    if isinstance(module, dict) and 'config' in module:
        return jsonify({
            'module': module_name,
            'config': module['config'],
            'timestamp': datetime.now().isoformat()
        })

    return jsonify({'error': 'Configuration not available'}), 400


# ============================================================================
# API Routes - Operations
# ============================================================================

@app.route('/api/operations', methods=['GET'])
def list_operations():
    """List all active operations"""
    operations_list = []

    for op_id, op_data in active_operations.items():
        operations_list.append({
            'id': op_id,
            'name': op_data.get('name'),
            'status': op_data.get('status'),
            'started_at': op_data.get('started_at'),
            'progress': op_data.get('progress', 0),
            'findings': len(op_data.get('findings', []))
        })

    return jsonify({
        'operations': operations_list,
        'total': len(operations_list),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/operations/run-full', methods=['POST'])
def run_full_operation():
    """Run full red team operation (5 phases)"""
    global orchestrator

    if not orchestrator:
        return jsonify({'error': 'Orchestrator not initialized'}), 400

    op_id = secrets.token_hex(8)

    try:
        # Create operation record
        active_operations[op_id] = {
            'id': op_id,
            'name': 'Full Red Team Operation',
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'progress': 0,
            'phases': {},
            'findings': []
        }

        log_operation('OPERATION', f'Started full red team operation: {op_id}')

        # Run in background thread
        def run_operation():
            try:
                active_operations[op_id]['progress'] = 20
                active_operations[op_id]['status'] = 'phase_1'

                result = orchestrator.run_full_red_team_operation()

                active_operations[op_id]['progress'] = 100
                active_operations[op_id]['status'] = 'completed'
                active_operations[op_id]['result'] = result

                log_operation('OPERATION', f'Completed operation: {op_id}')
            except Exception as e:
                active_operations[op_id]['status'] = 'failed'
                active_operations[op_id]['error'] = str(e)
                log_operation('ERROR', f'Operation failed: {str(e)}')

        thread = Thread(target=run_operation, daemon=True)
        thread.start()

        return jsonify({
            'operation_id': op_id,
            'status': 'started',
            'message': 'Full red team operation started',
            'timestamp': datetime.now().isoformat()
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/operations/<op_id>', methods=['GET'])
def get_operation(op_id):
    """Get operation details"""
    if op_id not in active_operations:
        return jsonify({'error': 'Operation not found'}), 404

    op = active_operations[op_id]

    return jsonify({
        'id': op['id'],
        'name': op.get('name'),
        'status': op.get('status'),
        'started_at': op.get('started_at'),
        'progress': op.get('progress'),
        'phases': op.get('phases', {}),
        'findings': len(op.get('findings', [])),
        'result': op.get('result'),
        'error': op.get('error'),
        'timestamp': datetime.now().isoformat()
    })


# ============================================================================
# API Routes - C2 Framework
# ============================================================================

@app.route('/api/c2/beacons', methods=['GET'])
def list_beacons():
    """List all active beacons"""
    global orchestrator

    if not orchestrator or 'c2_framework' not in orchestrator.modules:
        return jsonify({'error': 'C2 not initialized'}), 400

    c2 = orchestrator.modules['c2_framework']['controller']
    sessions = c2.list_active_sessions()

    return jsonify({
        'beacons': sessions,
        'total': len(sessions),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/c2/beacon/create', methods=['POST'])
def create_beacon():
    """Create new beacon with specified profile"""
    global orchestrator

    if not orchestrator or 'c2_framework' not in orchestrator.modules:
        return jsonify({'error': 'C2 not initialized'}), 400

    data = request.get_json()
    profile_name = data.get('profile', 'azure')

    c2 = orchestrator.modules['c2_framework']['controller']
    beacon = c2.register_beacon(profile_name)

    log_operation('C2', f'Beacon created: {beacon.beacon_id} (profile: {profile_name})')

    return jsonify({
        'beacon_id': beacon.beacon_id,
        'profile': profile_name,
        'session_key': beacon.session_key.hex()[:32] + '...',
        'created_at': datetime.now().isoformat()
    })


@app.route('/api/c2/beacon/<beacon_id>/command', methods=['POST'])
def execute_beacon_command(beacon_id):
    """Execute command on beacon"""
    global orchestrator

    if not orchestrator or 'c2_framework' not in orchestrator.modules:
        return jsonify({'error': 'C2 not initialized'}), 400

    c2 = orchestrator.modules['c2_framework']['controller']
    beacon = c2.get_session(beacon_id)

    if not beacon:
        return jsonify({'error': 'Beacon not found'}), 404

    data = request.get_json()
    command = data.get('command')
    args = data.get('args', [])

    result = beacon.execute_command(command, args)

    log_operation('C2', f'Command executed on {beacon_id}: {command}')

    return jsonify({
        'beacon_id': beacon_id,
        'command': command,
        'args': args,
        'result': result,
        'timestamp': datetime.now().isoformat()
    })


# ============================================================================
# API Routes - BAS & Assessment
# ============================================================================

@app.route('/api/bas/playbooks', methods=['GET'])
def list_playbooks():
    """List available playbooks"""
    playbooks = list(Playbook.PREDEFINED_PLAYBOOKS.keys())

    return jsonify({
        'playbooks': playbooks,
        'total': len(playbooks),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/bas/run-playbook', methods=['POST'])
def run_playbook():
    """Run specific playbook"""
    global orchestrator

    if not orchestrator or 'bas_engine' not in orchestrator.modules:
        return jsonify({'error': 'BAS not initialized'}), 400

    data = request.get_json()
    playbook_name = data.get('playbook')

    if playbook_name not in Playbook.PREDEFINED_PLAYBOOKS:
        return jsonify({'error': f'Playbook not found: {playbook_name}'}), 404

    op_id = secrets.token_hex(8)

    try:
        active_operations[op_id] = {
            'id': op_id,
            'name': f'Playbook: {playbook_name}',
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'progress': 0,
            'playbook': playbook_name
        }

        def run_pb():
            try:
                runner = orchestrator.modules['bas_engine']['runner']
                playbook = Playbook.from_preset(playbook_name)
                result = runner.run_playbook(playbook)

                active_operations[op_id]['status'] = 'completed'
                active_operations[op_id]['progress'] = 100
                active_operations[op_id]['result'] = result

                log_operation('BAS', f'Playbook completed: {playbook_name}')
            except Exception as e:
                active_operations[op_id]['status'] = 'failed'
                active_operations[op_id]['error'] = str(e)

        thread = Thread(target=run_pb, daemon=True)
        thread.start()

        return jsonify({
            'operation_id': op_id,
            'playbook': playbook_name,
            'status': 'started',
            'timestamp': datetime.now().isoformat()
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bas/full-assessment', methods=['POST'])
def full_assessment():
    """Run full BAS assessment (all playbooks)"""
    global orchestrator

    if not orchestrator or 'bas_engine' not in orchestrator.modules:
        return jsonify({'error': 'BAS not initialized'}), 400

    op_id = secrets.token_hex(8)

    try:
        active_operations[op_id] = {
            'id': op_id,
            'name': 'Full BAS Assessment',
            'status': 'running',
            'started_at': datetime.now().isoformat(),
            'progress': 0
        }

        def run_assessment():
            try:
                runner = orchestrator.modules['bas_engine']['runner']
                result = runner.run_full_assessment()

                active_operations[op_id]['status'] = 'completed'
                active_operations[op_id]['progress'] = 100
                active_operations[op_id]['result'] = result
                active_operations[op_id]['findings'] = result.get('total_findings', 0)

                log_operation('BAS', 'Full assessment completed')
            except Exception as e:
                active_operations[op_id]['status'] = 'failed'
                active_operations[op_id]['error'] = str(e)

        thread = Thread(target=run_assessment, daemon=True)
        thread.start()

        return jsonify({
            'operation_id': op_id,
            'status': 'started',
            'message': 'Full assessment started',
            'timestamp': datetime.now().isoformat()
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API Routes - Reporting
# ============================================================================

@app.route('/api/reporting/generate', methods=['POST'])
def generate_report():
    """Generate automated report from findings"""
    global orchestrator

    if not orchestrator or 'reporting' not in orchestrator.modules:
        return jsonify({'error': 'Reporting not initialized'}), 400

    data = request.get_json()
    findings_data = data.get('findings', [])

    try:
        jinja_gen = orchestrator.modules['reporting']['jinja_generator']
        exporter = orchestrator.modules['reporting']['exporter']

        report_data = {
            'report_id': secrets.token_hex(8),
            'assessment_date': datetime.now().isoformat(),
            'duration_hours': data.get('duration', 1.5),
            'total_findings': len(findings_data),
            'risk_level': data.get('risk_level', 'High'),
            'overview': 'Assessment completed',
            'critical_count': len([f for f in findings_data if f.get('severity') == 'critical']),
            'high_count': len([f for f in findings_data if f.get('severity') == 'high']),
            'medium_count': len([f for f in findings_data if f.get('severity') == 'medium']),
            'findings': findings_data,
        }

        report = jinja_gen.generate_full_report(report_data)

        log_operation('REPORT', f'Report generated: {report_data["report_id"]}')

        return jsonify({
            'report_id': report_data['report_id'],
            'sections': list(report['sections'].keys()),
            'findings': len(findings_data),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API Routes - Evasion Testing
# ============================================================================

@app.route('/api/evasion/sandbox-check', methods=['POST'])
def sandbox_check():
    """Check for sandbox/analysis environment"""
    try:
        detector = SandboxDetector()
        findings = detector.check_all()

        result = {
            'is_sandboxed': len(findings) > 0,
            'detections': findings,
            'safe_to_execute': len(findings) == 0,
            'timestamp': datetime.now().isoformat()
        }

        log_operation('EVASION', f'Sandbox check completed: {result["detections"]}')

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/evasion/sleep-obfuscate', methods=['POST'])
def sleep_obfuscate():
    """Test sleep obfuscation"""
    data = request.get_json()
    duration_ms = data.get('duration', 10000)

    try:
        obfuscator = SleepObfuscator()
        result = obfuscator.obfuscate_sleep(duration_ms)

        log_operation('EVASION', f'Sleep obfuscation tested: {duration_ms}ms')

        return jsonify({
            'status': 'success',
            'duration_requested': result['duration_requested_ms'],
            'duration_actual': result['duration_actual_ms'],
            'encrypted': result['encrypted_section_size'],
            'stack_spoofed': result['stack_spoofed'],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API Routes - Logging & Analytics
# ============================================================================

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get operation logs"""
    limit = request.args.get('limit', 100, type=int)

    return jsonify({
        'logs': operation_logs[-limit:],
        'total': len(operation_logs),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/analytics/dashboard', methods=['GET'])
def dashboard_analytics():
    """Get dashboard analytics"""
    global orchestrator

    try:
        total_ops = len(active_operations)
        completed_ops = len([op for op in active_operations.values() if op['status'] == 'completed'])
        total_findings = sum(op.get('findings', 0) for op in active_operations.values())

        return jsonify({
            'statistics': {
                'total_operations': total_ops,
                'completed_operations': completed_ops,
                'total_findings': total_findings,
                'modules_active': len(orchestrator.modules) if orchestrator else 0,
            },
            'recent_operations': [
                {
                    'id': op['id'],
                    'name': op['name'],
                    'status': op['status'],
                    'progress': op.get('progress', 0)
                }
                for op in list(active_operations.values())[-5:]
            ],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# API Routes - DDoS Testing
# ============================================================================

ddos_engine = DDoSTestingEngine()


@app.route('/api/ddos/methods', methods=['GET'])
def get_ddos_methods():
    """List available DDoS methods"""
    return jsonify({
        'methods': [
            {
                'id': 'syn_flood',
                'name': 'SYN Flood',
                'layer': 'Layer 4 (TCP)',
                'description': 'Floods target with SYN packets'
            },
            {
                'id': 'udp_flood',
                'name': 'UDP Flood',
                'layer': 'Layer 4 (UDP)',
                'description': 'Floods target with UDP packets'
            },
            {
                'id': 'http_flood',
                'name': 'HTTP Flood',
                'layer': 'Layer 7 (Application)',
                'description': 'Floods target with HTTP requests'
            },
            {
                'id': 'slowloris',
                'name': 'Slowloris',
                'layer': 'Layer 7 (Application)',
                'description': 'Keeps connections open to exhaust resources'
            },
            {
                'id': 'dns_amplification',
                'name': 'DNS Amplification',
                'layer': 'Layer 3 (Network)',
                'description': 'Amplifies traffic via DNS servers'
            }
        ],
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/ddos/start', methods=['POST'])
def start_ddos_test():
    """Start a DDoS test"""
    data = request.get_json()

    target_host = data.get('target_host')
    target_port = data.get('target_port', 80)
    method = data.get('method', 'http_flood')
    duration = data.get('duration', 60)
    pps = data.get('pps', 100)  # packets per second

    # Validate authorization
    if not _validate_ddos_authorization(target_host):
        log_operation('DDoS', f'UNAUTHORIZED: Attempted test against {target_host}')
        return jsonify({
            'error': 'Target not authorized',
            'message': 'DDoS tests only allowed on localhost and private IP ranges'
        }), 403

    try:
        config = DDoSConfig(
            target_host=target_host,
            target_port=target_port,
            method=DDoSMethod(method),
            duration_seconds=duration,
            threads=data.get('threads', 4),
            packets_per_second=pps,
            authorized=True,
            test_name=data.get('test_name', f'{method} test')
        )

        if method == 'syn_flood':
            result = ddos_engine.start_syn_flood(config)
        elif method == 'udp_flood':
            result = ddos_engine.start_udp_flood(config)
        elif method == 'http_flood':
            result = ddos_engine.start_http_flood(config)
        elif method == 'slowloris':
            result = ddos_engine.start_slowloris(config)
        elif method == 'dns_amplification':
            result = ddos_engine.start_dns_amplification(config)
        else:
            return jsonify({'error': 'Unknown method'}), 400

        log_operation('DDoS', f'Test started: {result.get("test_id")}')

        return jsonify(result), 202

    except Exception as e:
        log_operation('ERROR', f'DDoS test failed: {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/ddos/stop/<test_id>', methods=['POST'])
def stop_ddos_test(test_id):
    """Stop active DDoS test"""
    try:
        result = ddos_engine.stop_test(test_id)
        log_operation('DDoS', f'Test stopped: {test_id}')
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ddos/status/<test_id>', methods=['GET'])
def get_ddos_status(test_id):
    """Get DDoS test status"""
    try:
        status = ddos_engine.get_test_status(test_id)
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ddos/active', methods=['GET'])
def get_active_ddos_tests():
    """List active DDoS tests"""
    tests = ddos_engine.list_active_tests()
    return jsonify({
        'tests': tests,
        'total': len(tests),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/ddos/results', methods=['GET'])
def get_ddos_results():
    """Get completed DDoS test results"""
    results = ddos_engine.get_test_results()
    return jsonify({
        'results': results,
        'total': len(results),
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/ddos/config', methods=['GET'])
def get_ddos_config():
    """Get DDoS module configuration"""
    return jsonify(ddos_engine.export_config())


def _validate_ddos_authorization(target_host: str) -> bool:
    """Validate if target is authorized for DDoS testing"""
    # Only allow localhost and private IP ranges
    authorized_ranges = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
    return any(target_host.startswith(r) for r in authorized_ranges)


# ============================================================================
# Frontend Routes
# ============================================================================

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html', version='4.0')


@app.route('/modules')
def modules_page():
    """Modules management page"""
    return render_template('modules.html')


@app.route('/c2')
def c2_page():
    """C2 beacon management"""
    return render_template('c2.html')


@app.route('/bas')
def bas_page():
    """BAS playbook execution"""
    return render_template('bas.html')


@app.route('/operations')
def operations_page():
    """Operations monitoring"""
    return render_template('operations.html')


@app.route('/reporting')
def reporting_page():
    """Report generation"""
    return render_template('reporting.html')


@app.route('/evasion')
def evasion_page():
    """Evasion testing"""
    return render_template('evasion.html')


@app.route('/ddos')
def ddos_page():
    """DDoS testing"""
    return render_template('ddos.html')


# ============================================================================
# Helper Functions
# ============================================================================

def log_operation(operation_type: str, message: str):
    """Log operation to history"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'type': operation_type,
        'message': message
    }
    operation_logs.append(log_entry)
    print(f"[{log_entry['timestamp']}] [{operation_type}] {message}")


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500


# ============================================================================
# Main
# ============================================================================

if __name__ == '__main__':
    print("""
[*] PenteIA v4.0 - Web Dashboard
[*] Starting Flask application...
[*] Access at: http://localhost:5000
    """)

    # Create templates directory if not exists
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Run Flask app
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        use_reloader=False
    )
