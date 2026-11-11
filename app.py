
import os
import json
import joblib
import pandas as pd

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse

from feature_extractor import extract_url_features


app = Flask(__name__)

# Project directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

# Load trained model
model_path = os.path.join(MODEL_DIR, "phishing_model.pkl")
feature_path = os.path.join(MODEL_DIR, "feature_names.json")
info_path = os.path.join(MODEL_DIR, "model_info.json")

model = joblib.load(model_path)

with open(feature_path, "r") as file:
    feature_names = json.load(file)

with open(info_path, "r") as file:
    model_info = json.load(file)

threshold = float(model_info.get("threshold", 0.50))

# Verify model compatibility
if len(feature_names) != model.n_features_in_:
    raise ValueError("Model and feature count do not match!")


print("Phishing detection model loaded successfully!")
print("Model:", model_info.get("model_name", "Random Forest"))
print("Features:", len(feature_names))
print("Threshold:", threshold)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_url():

    try:
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()

        # Check empty input
        if not url:
            return jsonify({
                "error": "Please enter a URL."
            }), 400

        # Validate URL format without visiting the website
        parse_url = url if "://" in url else "http://" + url
        parsed = urlparse(parse_url)

        try:
            hostname = parsed.hostname
        except ValueError:
            hostname = None

        if not hostname or "." not in hostname:
            return jsonify({
                "error": "Please enter a valid URL."
            }), 400

        # Extract the 23 model features
        extracted_features = extract_url_features(url)

        # Arrange features in the exact model order
        feature_values = [
            extracted_features[name]
            for name in feature_names
        ]

        input_df = pd.DataFrame(
            [feature_values],
            columns=feature_names
        )

        # Get phishing probability (class 0 = phishing)
        probabilities = model.predict_proba(input_df)[0]

        phishing_index = list(model.classes_).index(0)
        phishing_probability = float(
            probabilities[phishing_index]
        )

        # Apply saved classification threshold
        if phishing_probability >= threshold:
            prediction = "Phishing"
            confidence = phishing_probability * 100
            message = "Warning! This URL shows phishing characteristics."
        else:
            prediction = "Legitimate"
            confidence = (1 - phishing_probability) * 100
            message = "This URL appears legitimate based on the model."

        return jsonify({
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "phishing_probability": round(
                phishing_probability * 100, 2
            ),
            "message": message
        })

    except Exception as error:
        print("Scanning error:", error)

        return jsonify({
            "error": "An error occurred while analyzing the URL."
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
