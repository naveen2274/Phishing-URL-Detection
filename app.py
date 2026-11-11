
import os
import json
import sqlite3
import joblib
import pandas as pd

from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify
from feature_extractor import extract_url_features


app = Flask(__name__)

# --------------------------------------------------
# PROJECT PATHS
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_PATH = os.path.join(MODEL_DIR, "feature_names.json")
INFO_PATH = os.path.join(MODEL_DIR, "model_info.json")

# SQLite database. Set DB_PATH in the environment if needed.
DB_PATH = os.environ.get(
    "DB_PATH",
    os.path.join(BASE_DIR, "scans.db")
)

# --------------------------------------------------
# LOAD MODEL
# --------------------------------------------------

model = joblib.load(MODEL_PATH)

with open(FEATURE_PATH, "r") as file:
    feature_names = json.load(file)

with open(INFO_PATH, "r") as file:
    model_info = json.load(file)

threshold = float(model_info.get("threshold", 0.50))

if len(feature_names) != model.n_features_in_:
    raise ValueError("Model and feature count do not match!")

if 0 not in model.classes_ or 1 not in model.classes_:
    raise ValueError("Expected model classes: 0=Phishing, 1=Legitimate")

if not hasattr(model, "predict_proba"):
    raise ValueError("The loaded model does not support predict_proba.")

print("Phishing detection model loaded successfully!")
print("Model:", model_info.get("model_name", "Random Forest"))
print("Features:", len(feature_names))
print("Threshold:", threshold)
print("Model classes:", model.classes_)


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db_connection():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    folder = os.path.dirname(DB_PATH)

    if folder:
        os.makedirs(folder, exist_ok=True)

    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            phishing_probability REAL NOT NULL,
            scanned_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()

    print("Scan database initialized:", DB_PATH)


initialize_database()


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def validate_url(url):
    """Validate URL format without visiting the website."""

    if not url or len(url) > 2048:
        return None

    candidate = url if "://" in url else "http://" + url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
    except ValueError:
        return None

    if parsed.scheme not in ("http", "https"):
        return None

    if not hostname or "." not in hostname:
        return None

    if any(char.isspace() for char in url):
        return None

    return parsed


def get_dashboard_statistics():
    connection = get_db_connection()

    row = connection.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN prediction = 'Phishing'
                THEN 1 ELSE 0 END) AS phishing,
            SUM(CASE WHEN prediction = 'Legitimate'
                THEN 1 ELSE 0 END) AS legitimate
        FROM scans
    """).fetchone()

    total = row["total"] or 0
    phishing = row["phishing"] or 0
    legitimate = row["legitimate"] or 0

    # This is the percentage of scanned URLs classified as phishing.
    # It is not model accuracy or recall.
    detection_rate = (
        (phishing / total) * 100 if total else 0
    )

    connection.close()

    return {
        "total_scans": total,
        "phishing_count": phishing,
        "legitimate_count": legitimate,
        "detection_rate": round(detection_rate, 2)
    }


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# SCAN URL API
# --------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def scan_url():

    try:
        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()

        if not url:
            return jsonify({
                "error": "Please enter a URL."
            }), 400

        parsed = validate_url(url)

        if not parsed:
            return jsonify({
                "error": "Please enter a valid HTTP or HTTPS URL."
            }), 400

        # Extract exactly the 23 training features.
        extracted_features = extract_url_features(url)

        missing_features = [
            name for name in feature_names
            if name not in extracted_features
        ]

        if missing_features:
            raise ValueError(
                "Missing model features: " + str(missing_features)
            )

        feature_values = [
            extracted_features[name]
            for name in feature_names
        ]

        input_df = pd.DataFrame(
            [feature_values],
            columns=feature_names
        )

        # Predict probabilities.
        probabilities = model.predict_proba(input_df)[0]

        classes = list(model.classes_)
        phishing_index = classes.index(0)
        legitimate_index = classes.index(1)

        phishing_probability = float(
            probabilities[phishing_index]
        )

        legitimate_probability = float(
            probabilities[legitimate_index]
        )

        # Debug output for Render logs.
        print("\n========== SCAN DEBUG ==========")
        print("URL:", url)
        print("Features:", extracted_features)
        print("Phishing probability:", phishing_probability)
        print("Legitimate probability:", legitimate_probability)
        print("Threshold:", threshold)
        print("================================\n")

        # Apply the saved threshold.
        if phishing_probability >= threshold:
            prediction = "Phishing"
            message = (
                "Warning! This URL shows phishing characteristics."
            )
            confidence = phishing_probability * 100
        else:
            prediction = "Legitimate"
            message = (
                "This URL appears legitimate based on the model."
            )
            confidence = legitimate_probability * 100

        # Save every successful scan.
        scanned_at = datetime.now(timezone.utc).isoformat()

        connection = get_db_connection()

        connection.execute("""
            INSERT INTO scans (
                url,
                prediction,
                confidence,
                phishing_probability,
                scanned_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            url,
            prediction,
            round(confidence, 2),
            round(phishing_probability * 100, 2),
            scanned_at
        ))

        connection.commit()
        connection.close()

        return jsonify({
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "phishing_probability": round(
                phishing_probability * 100, 2
            ),
            "legitimate_probability": round(
                legitimate_probability * 100, 2
            ),
            "message": message
        })

    except Exception as error:
        print("Scanning error:", repr(error))

        return jsonify({
            "error": "An error occurred while analyzing the URL."
        }), 500


# --------------------------------------------------
# DASHBOARD STATISTICS API
# --------------------------------------------------

@app.route("/api/dashboard", methods=["GET"])
def dashboard():

    try:
        stats = get_dashboard_statistics()

        connection = get_db_connection()

        # Last 7 days, including today (UTC).
        daily_rows = connection.execute("""
            SELECT
                date(scanned_at) AS scan_date,
                COUNT(*) AS total,
                SUM(CASE WHEN prediction = 'Phishing'
                    THEN 1 ELSE 0 END) AS phishing,
                SUM(CASE WHEN prediction = 'Legitimate'
                    THEN 1 ELSE 0 END) AS legitimate
            FROM scans
            WHERE date(scanned_at) >= date('now', '-6 days')
            GROUP BY date(scanned_at)
            ORDER BY scan_date ASC
        """).fetchall()

        connection.close()

        daily_data = {
            row["scan_date"]: {
                "total": row["total"],
                "phishing": row["phishing"] or 0,
                "legitimate": row["legitimate"] or 0
            }
            for row in daily_rows
        }

        chart_data = []

        today = datetime.now(timezone.utc).date()

        for days_ago in range(6, -1, -1):
            day = today - timedelta(days=days_ago)
            day_key = day.isoformat()

            values = daily_data.get(day_key, {})

            chart_data.append({
                "date": day_key,
                "total": values.get("total", 0),
                "phishing": values.get("phishing", 0),
                "legitimate": values.get("legitimate", 0)
            })

        return jsonify({
            "stats": stats,
            "analytics": chart_data
        })

    except Exception as error:
        print("Dashboard error:", repr(error))

        return jsonify({
            "error": "Unable to load dashboard statistics."
        }), 500


# --------------------------------------------------
# SCAN HISTORY API
# --------------------------------------------------

@app.route("/api/history", methods=["GET"])
def scan_history():

    try:
        connection = get_db_connection()

        rows = connection.execute("""
            SELECT
                id,
                url,
                prediction,
                confidence,
                phishing_probability,
                scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

        connection.close()

        history = [dict(row) for row in rows]

        return jsonify({
            "history": history
        })

    except Exception as error:
        print("History error:", repr(error))

        return jsonify({
            "error": "Unable to load scan history."
        }), 500


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "model_loaded": True,
        "database": "connected"
    })


# --------------------------------------------------
# RUN LOCAL SERVER
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
