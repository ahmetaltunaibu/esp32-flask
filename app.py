from flask import Flask, request, jsonify, render_template
from datetime import datetime
import time

app = Flask(__name__)

# Cihaz verilerini saklamak için
cihazlar = {}

@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    cihaz_id = data.get('cihaz_id')
    
    if cihaz_id:
        data['timestamp'] = int(time.time() * 1000)  # Milisaniye cinsinden timestamp
        cihazlar[cihaz_id] = data
        return jsonify({"status": "success", "message": "Data received"})
    return jsonify({"status": "error", "message": "Invalid data"}), 400

@app.route('/')
def index():
    current_time = int(time.time() * 1000)  # Şu anki zamanı milisaniye cinsinden
    return render_template('index.html', cihazlar=cihazlar, now=current_time)

@app.route('/cihaz/<cihaz_id>')
def cihaz_detay(cihaz_id):
    return render_template('cihaz_detay.html', cihaz=cihazlar.get(cihaz_id))

if __name__ == '__main__':
    app.run(debug=True)
