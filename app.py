from flask import Flask, request, jsonify, render_template
import json
from datetime import datetime

app = Flask(__name__)

# Verileri saklamak için basit bir liste
received_data = []

@app.route('/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    received_data.append(data)
    
    # Son 10 kaydı tut
    if len(received_data) > 10:
        received_data.pop(0)
    
    print("Received data:", data)
    return jsonify({"status": "success", "message": "Data received"})

@app.route('/')
def index():
    return render_template('index.html', data=received_data)

if __name__ == '__main__':
    app.run(debug=True)
