from flask import Flask, request, render_template_string

app = Flask(__name__)
current_temperature = None

@app.route("/data", methods=["POST"])
def receive_data():
    global current_temperature
    data = request.get_json()
    current_temperature = data.get("temperature")
    return "OK"

@app.route("/")
def index():
    return render_template_string("""
        <h1>ESP32 Sıcaklık Verisi</h1>
        <p>Mevcut sıcaklık: {{ temp }} °C</p>
    """, temp=current_temperature or "Henüz veri yok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
