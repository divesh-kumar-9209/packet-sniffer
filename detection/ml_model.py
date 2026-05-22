from sklearn.ensemble import IsolationForest
import numpy as np

model = IsolationForest(contamination=0.05)

data_buffer = []

def extract_features(packet_count, port_count):
    return [packet_count, port_count]

def train_model():
    global model
    if len(data_buffer) > 50:
        model.fit(data_buffer)

def predict_anomaly(packet_count, port_count):
    features = extract_features(packet_count, port_count)
    data_buffer.append(features)

    if len(data_buffer) < 20:
        return 0  # not enough data

    pred = model.predict([features])[0]

    return 100 if pred == -1 else 0