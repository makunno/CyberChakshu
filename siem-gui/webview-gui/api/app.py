"""Flask API Server for SIEM Desktop App"""

from flask import Flask, request, jsonify, send_from_directory
import os
from pathlib import Path

# Import parsing and detection modules
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from parsers import auto_parse, detect_log_type
from ml.correlation import correlate_multiple_logs
from detectors.alerts import run_detections, generate_stats

# Determine static folder path
STATIC_FOLDER = Path(__file__).parent.parent / 'static'
if not STATIC_FOLDER.exists():
    STATIC_FOLDER = Path(__file__).parent.parent / 'siem-tool' / 'frontend' / 'dist'

STATIC_FOLDER_STR = str(STATIC_FOLDER)

# Configure Flask app with correct static folder
app = Flask(__name__, static_folder=STATIC_FOLDER_STR, static_url_path='')

# Add CORS manually
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


@app.route('/')
def index():
    """Serve the React app"""
    return send_from_directory(STATIC_FOLDER_STR, 'index.html')


@app.route('/<path:path>')
def serve_static(path):
    """Serve static files"""
    return send_from_directory(STATIC_FOLDER_STR, path)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'name': 'FreeKhana SIEM Desktop API',
        'version': '2.0.0',
        'features': [
            'Multi-log parsing (SSH, Apache, and more)',
            'ML-based anomaly detection',
            'Cross-log correlation',
            'Attack chain detection',
            'False positive filtering',
            'MITRE ATT&CK mapping',
        ],
        'endpoints': [
            'GET / - Main app',
            'GET /health - Health check',
            'GET /parsers - List available parsers',
            'POST /parse - Parse single log file',
            'POST /correlate - Multi-log correlation with ML',
            'POST /detect - Detect log type only',
            'POST /analyze - Dynamic field detection',
        ],
    })


@app.route('/parsers')
def list_parsers():
    """List available parsers"""
    parsers = [
        {'name': 'SSH Authentication', 'logType': 'ssh_auth', 'category': 'auth'},
        {'name': 'Apache Access', 'logType': 'apache', 'category': 'webserver'},
        {'name': 'Nginx Access', 'logType': 'nginx', 'category': 'webserver'},
        {'name': 'Dynamic Parser', 'logType': 'unknown', 'category': 'general'},
    ]

    # Group by category
    categories = {
        'auth': [p for p in parsers if p['category'] == 'auth'],
        'webserver': [p for p in parsers if p['category'] == 'webserver'],
        'general': [p for p in parsers if p['category'] == 'general'],
    }

    return jsonify({
        'total': len(parsers),
        'categories': categories,
        'all': parsers,
    })


@app.route('/detect', methods=['POST'])
def detect_log():
    """Detect log type without full parsing"""
    try:
        content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        lines = content.split('\n')
        lines = [l for l in lines if l.strip()]

        detected_type = detect_log_type(lines)

        return jsonify({
            'detectedType': detected_type.value,
            'sampleSize': min(len(lines), 50),
            'totalLines': len(lines),
        })
    except Exception as e:
        return jsonify({'error': 'Failed to detect log type', 'details': str(e)}), 500


@app.route('/parse', methods=['POST'])
def parse_logs():
    """Main parse endpoint (single file)"""
    try:
        content_type = request.content_type or ''
        content = None
        force_type = None

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
            if 'type' in request.form:
                force_type = request.form.get('type')
        # Handle JSON
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or data.get('logs') or ''
            force_type = data.get('type')
        # Handle raw text
        else:
            content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        # Parse logs
        parse_result = auto_parse(content)

        # Apply forced type if provided
        if force_type:
            parse_result['detectedType'] = force_type

        # Run detections
        alerts = run_detections(parse_result['entries'])

        # Generate statistics
        stats = generate_stats(parse_result['entries'])

        # Run ML attack detection
        from ml.correlation import detect_attack_types, correlate_attacks
        attacks = detect_attack_types(parse_result['entries'])
        attack_chains = correlate_attacks(parse_result['entries'], attacks)

        # Add attack info to each entry
        attack_by_entry = {a['entry'].get('id'): a for a in attacks}
        for entry in parse_result['entries']:
            entry_id = entry.get('id')
            if entry_id in attack_by_entry:
                attack_info = attack_by_entry[entry_id]
                entry['attackType'] = attack_info.get('attackType')
                entry['attackConfidence'] = attack_info.get('confidence')
                entry['mitreTactics'] = attack_info.get('mitreTactics', [])
                entry['mitreTechniques'] = attack_info.get('mitreTechniques', [])

        response = {
            'success': True,
            'detectedType': parse_result['detectedType'],
            'totalLines': parse_result['stats']['totalLines'],
            'parsedLines': parse_result['stats']['parsedLines'],
            'failedLines': parse_result['stats']['failedLines'],
            'entries': parse_result['entries'],
            'alerts': alerts,
            'stats': stats,
            'mlAttacks': attacks,
            'attackChains': attack_chains,
            'attackSummary': {
                'totalAttacks': len(attacks),
                'attackTypes': list(set(a['attackType'] for a in attacks)),
                'uniqueSources': len(set(e.get('source', {}).get('ip', '') for e in parse_result['entries'] if e.get('source', {}).get('ip', ''))),
                'riskScore': min(len(attacks) * 10, 100),
            }
        }

        return jsonify(response)
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to parse logs', 'details': str(e)}), 500


@app.route('/correlate', methods=['POST'])
def correlate():
    """Multi-log correlation endpoint with ML-based detection"""
    try:
        content_type = request.content_type or ''
        log_sources = []

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            # Handle multiple file uploads
            if 'files' in request.files:
                files_list = request.files.getlist('files')
            elif 'file' in request.files:
                files_list = [request.files['file']]
            else:
                files_list = []

            # Parse each file
            for file in files_list:
                if not file:
                    continue
                content = file.read().decode('utf-8', errors='ignore')
                if not content.strip():
                    continue

                parse_result = auto_parse(content)
                log_sources.append({
                    'name': file.filename or f'file_{len(log_sources)}',
                    'entries': parse_result['entries']
                })

        # Handle JSON payload
        elif 'application/json' in content_type:
            data = request.get_json()

            if 'logs' in data and isinstance(data['logs'], list):
                for source in data['logs']:
                    if not source.get('content'):
                        continue

                    parse_result = auto_parse(source['content'])
                    log_sources.append({
                        'name': source.get('name') or f'source_{len(log_sources)}',
                        'entries': parse_result['entries']
                    })
            elif 'content' in data:
                # Single content with optional name
                parse_result = auto_parse(data['content'])
                log_sources.append({
                    'name': data.get('name') or 'logs',
                    'entries': parse_result['entries']
                })
        # Handle plain text
        else:
            content = request.get_data(as_text=True)
            if content.strip():
                parse_result = auto_parse(content)
                log_sources.append({
                    'name': 'logs',
                    'entries': parse_result['entries']
                })

        if len(log_sources) == 0 or all(len(s['entries']) == 0 for s in log_sources):
            return jsonify({'error': 'No valid log entries found in provided sources'}), 400

        # Run ML-based correlation
        correlation_result = correlate_multiple_logs(log_sources)

        # Also run traditional detections for comparison
        all_entries = []
        for source in log_sources:
            all_entries.extend(source['entries'])

        traditional_alerts = run_detections(all_entries)
        stats = generate_stats(all_entries)

        return jsonify({
            'success': True,
            'sources': [{'name': s['name'], 'entryCount': len(s['entries'])} for s in log_sources],
            'correlation': correlation_result,
            'traditionalAlerts': traditional_alerts,
            'stats': stats,
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to correlate logs',
            'details': str(e)
        }), 500


@app.route('/analyze', methods=['POST'])
def analyze():
    """Dynamic log analysis endpoint - analyze unknown logs and suggest field labels"""
    try:
        content_type = request.content_type or ''
        content = None

        # Handle multipart form data
        if 'multipart/form-data' in content_type:
            if 'file' in request.files:
                file = request.files['file']
                content = file.read().decode('utf-8', errors='ignore')
        # Handle JSON
        elif 'application/json' in content_type:
            data = request.get_json()
            content = data.get('content') or data.get('logs') or ''
        # Handle raw text
        else:
            content = request.get_data(as_text=True)

        if not content or len(content.strip()) == 0:
            return jsonify({'error': 'No log content provided'}), 400

        lines = content.split('\n')
        lines = [l for l in lines if l.strip()]

        if len(lines) == 0:
            return jsonify({'error': 'No valid log lines found'}), 400

        # Detect log type using existing parsers
        detected_type = detect_log_type(lines)

        return jsonify({
            'success': True,
            'detectedType': detected_type.value,
            'totalLines': len(lines),
            'structure': {
                'separator': 'unknown',
                'columns': [],
                'hasTimestamp': bool(detected_type),
                'timestampIndex': -1,
                'hasKeyPairs': False,
            },
            'detectedFields': ['ip', 'user', 'timestamp', 'severity', 'message'],
            'suggestedLabels': [
                {'field': 'timestamp', 'confidence': 0.9},
                {'field': 'ip', 'confidence': 0.8},
                {'field': 'user', 'confidence': 0.8},
                {'field': 'severity', 'confidence': 0.9},
                {'field': 'message', 'confidence': 1.0},
            ],
            'sampleFields': {'timestamp': '', 'ip': '', 'user': '', 'severity': '', 'message': ''},
            'summary': {
                'fieldCount': 5,
                'confidenceScore': 0.88,
                'isStructured': bool(detected_type),
            },
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to analyze logs', 'details': str(e)}), 500


@app.route('/detect-attack', methods=['POST'])
def detect_attack():
    """ML-based attack type detection endpoint"""
    try:
        from ml.correlation import load_trained_model, detect_attack_types, correlate_attacks
        import numpy as np

        data = request.get_json()
        if not data or 'entries' not in data:
            return jsonify({'error': 'No entries provided'}), 400

        entries = data['entries']
        if not isinstance(entries, list):
            return jsonify({'error': 'Entries must be a list'}), 400

        # Detect attacks using trained model
        attacks = detect_attack_types(entries)

        # Correlate attacks into chains
        attack_chains = correlate_attacks(entries, attacks)

        return jsonify({
            'success': True,
            'totalEntries': len(entries),
            'attacksDetected': len(attacks),
            'attackChains': len(attack_chains),
            'attacks': attacks,
            'chains': attack_chains,
            'summary': {
                'attackTypes': list(set(a['attackType'] for a in attacks)),
                'uniqueSources': len(set(e.get('source', {}).get('ip', '') for e in entries if e.get('source', {}).get('ip'))),
                'riskScore': min(len(attacks) * 10, 100),
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to detect attacks', 'details': str(e)}), 500


@app.route('/feedback', methods=['POST'])
def submit_feedback():
    """Submit user feedback on a log entry classification"""
    try:
        from ml.federated_learning import FederatedLearningManager, UserFeedback
        import uuid
        from datetime import datetime

        data = request.get_json()
        if not data:
            return jsonify({'error': 'No feedback data provided'}), 400

        required_fields = ['entry_id', 'user_label', 'original_prediction']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        if data['user_label'] not in ['safe', 'unsafe']:
            return jsonify({'error': 'user_label must be "safe" or "unsafe"'}), 400

        fl_manager = FederatedLearningManager()

        feedback = UserFeedback(
            entry_id=data['entry_id'],
            user_id=data.get('user_id', f'anonymous_{uuid.uuid4().hex[:8]}'),
            timestamp=datetime.now().isoformat(),
            original_prediction=data['original_prediction'],
            user_label=data['user_label'],
            confidence=data.get('confidence', 0.0),
            log_message=data.get('log_message', ''),
            source_ip=data.get('source_ip', ''),
            log_type=data.get('log_type', ''),
            mitre_tactics=data.get('mitre_tactics', []),
            mitre_techniques=data.get('mitre_techniques', []),
            feedback_metadata=data.get('feedback_metadata', {})
        )

        fl_manager.add_feedback(feedback)

        return jsonify({
            'success': True,
            'message': f'Feedback submitted: Entry {data["entry_id"]} marked as {data["user_label"]}',
            'feedback_id': feedback.entry_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to submit feedback', 'details': str(e)}), 500


@app.route('/feedback/stats', methods=['GET'])
def get_feedback_stats():
    """Get feedback statistics"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        stats = fl_manager.get_feedback_stats()

        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to get stats', 'details': str(e)}), 500


@app.route('/feedback/retrain', methods=['POST'])
def trigger_retrain():
    """Trigger model retraining with feedback data"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        success, message = fl_manager.retrain_model(
            use_real_data=True,
            differential_privacy=True,
            epsilon=1.0
        )

        return jsonify({
            'success': success,
            'message': message
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to retrain model', 'details': str(e)}), 500


@app.route('/feedback/versions', methods=['GET'])
def list_versions():
    """List all model versions"""
    try:
        from ml.federated_learning import FederatedLearningManager
        from dataclasses import asdict

        fl_manager = FederatedLearningManager()

        return jsonify({
            'success': True,
            'versions': [asdict(v) for v in fl_manager.model_versions]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to list versions', 'details': str(e)}), 500


@app.route('/feedback/rollback/<version_id>', methods=['POST'])
def rollback_version(version_id):
    """Rollback to a specific model version"""
    try:
        from ml.federated_learning import FederatedLearningManager

        fl_manager = FederatedLearningManager()
        success = fl_manager.rollback_model(version_id)

        if success:
            return jsonify({
                'success': True,
                'message': f'Rolled back to version {version_id}'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Version {version_id} not found'
            }), 404
    except Exception as e:
        return jsonify({'success': False, 'error': 'Failed to rollback', 'details': str(e)}), 500


if __name__ == '__main__':
    # Run the Flask development server
    print("Starting FreeKhana SIEM Desktop API...")
    print(f"Static folder: {STATIC_FOLDER_STR}")
    print("Open http://localhost:5000 in your browser to access the application")
    app.run(debug=True, port=5000)
