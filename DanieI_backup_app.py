from flask import Flask, request, jsonify
from flask_cors import CORS
import tensorflow as tf

app = Flask(__name__)

# Allow Firefox extension / local requests
CORS(app)

# Load trained phishing model
model = tf.keras.models.load_model("phishing_detector.keras")


@app.route("/")
def home():
    return "Phishing Detector API Running"


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No JSON data received"
            }), 400

        sender = data.get("sender", "")
        subject = data.get("subject", "")
        body = data.get("body", "")

        # Must match the format used during training
        text = (
            sender +
            " SUBJECT: " +
            subject +
            " BODY: " +
            body
        )

        # Convert to TensorFlow string tensor
        input_tensor = tf.constant(
            [text],
            dtype=tf.string
        )

        # Run model
        prediction = model(
            input_tensor,
            training=False
        )

        score = float(prediction[0][0])

        result = {
            "score": score,
            "label": "phishing" if score >= 0.5 else "legitimate"
        }

        return jsonify(result)

    except Exception as e:
        print("ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )