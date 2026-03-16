from flask import Flask, jsonify, send_file
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from honeypot_server import run_simulation, logger

app = Flask(__name__)

# شغل السيميولاشن بالخلفية
t = threading.Thread(target=run_simulation, daemon=True)
t.start()

@app.route('/')
def dashboard():
    return send_file('dashboard.html')

@app.route('/api/attacks')
def get_attacks():
    return jsonify(logger.get_all()[-50:])

@app.route('/api/stats')
def get_stats():
    return jsonify(logger.get_stats())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)