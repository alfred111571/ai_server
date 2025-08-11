from flask import Flask, request, jsonify
import joblib
import pandas as pd
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Load your trained model pipeline
model_path = r"C:\ai_server\logistic_regression_pipeline.pkl"
model = joblib.load(model_path)

expected_features = [
    "Flow Duration", "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
    "Total Length of Bwd Packet", "Fwd Packet Length Max", "Fwd Packet Length Min", 
    "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std", 
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max",
    "Bwd IAT Min", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", 
    "Bwd Packets/s", "Packet Length Min", "Packet Length Max", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", 
    "CWR Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
    "Fwd Segment Size Avg", "Bwd Segment Size Avg"
]

@app.route('/predict', methods=['POST'])
def predict():
    try:
        input_data = request.get_json()

        input_df = pd.DataFrame([input_data], columns=expected_features)

        missing = set(expected_features) - set(input_data.keys())
        extra = set(input_data.keys()) - set(expected_features)
        if missing or extra:
            return jsonify({
                'error': 'Feature names mismatch.',
                'missing_features': list(missing),
                'extra_features': list(extra)
            }), 400

        prediction = model.predict(input_df)
        result = "Yes" if prediction[0] == 1 else "No"

        return jsonify({'threat_detected': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/block_source', methods=['POST'])
def block_source():
    try:
        data = request.get_json()
        source_info = data.get('source', 'Unknown Source')
        print(f"🔴 Threat detected from: {source_info}. Action: Source blocked.")
        return jsonify({'status': 'Source blocked successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 📌 New: CSV prediction endpoint
@app.route('/predict_csv', methods=['POST'])
def predict_csv():
    try:
        data = request.get_json()
        csv_data = data.get('csv_data')
        if not csv_data:
            return jsonify({'success': False, 'error': 'No CSV data provided.'}), 400

        from io import StringIO
        df = pd.read_csv(StringIO(csv_data))

        if not all(f in df.columns for f in expected_features):
            missing = list(set(expected_features) - set(df.columns))
            return jsonify({'success': False, 'error': f'Missing columns: {missing}'}), 400

        predictions = model.predict(df[expected_features])

        results = []
        for pred in predictions:
            results.append({'threat_detected': "Yes" if pred == 1 else "No"})

        return jsonify({'success': True, 'results': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)

