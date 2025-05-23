from flask import Flask, request, render_template

app = Flask(__name__)

current_temperature = None  # Son alınan sıcaklık verisini saklama

@app.route("/data", methods=["POST"])
def receive_data():
    global current_temperature
    data = request.get_json()
    current_temperature = data.get("temperature")
    return "OK"

@app.route("/")
def index():
    return render_template("index.html", temp=current_temperature or "Henüz veri yok")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
