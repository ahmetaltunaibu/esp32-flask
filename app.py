from flask import Flask, request, jsonify, render_template
import json
from datetime import datetime

app = Flask(__name__)

# Verileri saklamak için
received_data = {
    'last_data': None,
    'history': []
}

@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Son veriyi güncelle
    received_data['last_data'] = data
    
    # Geçmişe ekle (son 10 kayıt)
    received_data['history'].append(data)
    if len(received_data['history']) > 10:
        received_data['history'].pop(0)
    
    print("Received data:", data)
    return jsonify({"status": "success", "message": "Data received"})

@app.route('/')
def index():
    return render_template('index.html', data=received_data['last_data'])

@app.route('/get_data')
def get_data():
    return jsonify(received_data['last_data'])

if __name__ == '__main__':
    app.run(debug=True)
