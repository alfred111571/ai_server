from flask import Flask, request, jsonify
import pandas as pd
import joblib

app = Flask(__name__)

# Load your trained model
model = joblib.load('threat_model.pkl')  # Update if your model file has a different name

@app.route('/predict', methods=['POST'])
def predict():
    # Get raw data sent from PHP
    log_data = request.form['log']

    # Process the data (convert to DataFrame if your model expects it)
    data_df = pd.DataFrame({'log': [log_data]})

    # Make prediction
    prediction = model.predict(data_df)

    # Return result
    return jsonify({'threat_detected': str(prediction[0])})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
