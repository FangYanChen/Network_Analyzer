from flask import Flask, render_template, jsonify
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app)

database = None


def init_app(db):
    """Initialize app with database"""
    global database
    database = db

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/stats/protocols')
def get_protocol_stats():
    """Get protocol statistics"""
    stats = database.get_protocol_stats()
    return jsonify(stats)

@app.route('/api/stats/services')
def get_service_stats():
    """Get service statistics"""
    stats = database.get_service_stats()
    return jsonify(stats)

@app.route('/api/stats/top-talkers')
def get_top_talkers():
    """Get most active IPs"""
    talkers = database.get_top_talkers()
    return jsonify(talkers)

@app.route('/api/packets/recent')
def get_recent_packets():
    """Get recent packets"""
    packets = database.get_recent_packets()
    return jsonify(packets)

@app.route('/api/alerts')
def get_alerts():
    """Get security alerts"""
    alerts = database.get_alerts()
    return jsonify(alerts)

@app.route('/api/stats/timeline')
def get_timeline():
    """Get traffic timeline"""
    timeline = database.get_traffic_timeline()
    return jsonify(timeline)

@app.route('/api/stats/total')
def get_total_stats():
    """Get overall statistics"""
    stats = database.get_total_stats()
    return jsonify(stats)

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'Network Analyzer API'})

def run_server(port=5000):
    """Run Flask server"""
    print(f"Web dashboard starting on http://localhost:{port}")
    app.run(debug=False, port=port, threaded=True)