import pandas as pd
import pickle
import time
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier

# Mock MongoDB collections using lists
packets_collection = []
blacklist_collection = []

# Load the encoder, scaler, and trained model
with open('model/encoder.pkl', 'rb') as encoder_file:
    encoder = pickle.load(encoder_file)
with open('model/scaler.pkl', 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)
with open('model/best_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Function to process and log packets
def process_packet(packet):
    packet_info = {
        "_id": packet["_id"],
        "timestamp": packet["timestamp"],
        "src": packet["src"],
        "dst": packet["dst"],
        "proto": packet["proto"],
        "sport": packet["sport"],
        "dport": packet["dport"],
        "payload": packet["payload"],
        "dur": packet.get("dur", 0),
        "sbytes": packet.get("sbytes", 0),
        "dbytes": packet.get("dbytes", 0),
        "sttl": packet.get("sttl", 0),
        "dttl": packet.get("dttl", 0),
        "sload": packet.get("sload", 0),
        "dload": packet.get("dload", 0),
        "sloss": packet.get("sloss", 0),
        "dloss": packet.get("dloss", 0),
        "swin": packet.get("swin", 0),
        "dwin": packet.get("dwin", 0),
        "stcpb": packet.get("stcpb", 0),
        "dtcpb": packet.get("dtcpb", 0),
        "state": packet.get("state", "-")
    }
    packets_collection.append(packet_info)
    print(f"Logged packet: {packet_info}")

# Function to analyze packets and update the blacklist
def analyze_packets():
    packets_df = pd.DataFrame(packets_collection)

    if not packets_df.empty:
        # Retain the non-numerical fields for the blacklist
        non_numerical_columns = ['_id', 'timestamp', 'src', 'dst', 'sport', 'dport', 'payload']
        selected_columns = ['proto', 'state', 'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'swin', 'dwin', 'stcpb', 'dtcpb']
        packets_df = packets_df[selected_columns]
        
        # Apply encoder transformation column-wise with handling for unknown values
        for col in ['proto', 'state']:
            packets_df[col] = packets_df[col].apply(lambda x: encoder.transform([x])[0] if x in encoder.classes_ else -1)

        packets_scaled = scaler.transform(packets_df)

        predictions = model.predict(packets_scaled)

        malicious_packets = packets_df[predictions == 1]

        if not malicious_packets.empty:
            blacklist_entries = []
            for index, row in malicious_packets.iterrows():
                blacklist_entries.append({
                    "src": packets_collection[index]['src'],
                    "dst": packets_collection[index]['dst'],
                    "proto": row['proto'],
                    "sport": packets_collection[index]['sport'],
                    "dport": packets_collection[index]['dport'],
                    "reason": "malicious activity detected"
                })
            blacklist_collection.extend(blacklist_entries)

        print("IDS analysis completed. Malicious packets added to the blacklist.")

# Function to test specific packets
def test_specific_packets(packets):
    for packet in packets:
        process_packet(packet)
    analyze_packets()

# Define three packets: two normal and one malicious
normal_packet_1 = {
    "_id": "66768d35016f267936560c04",
    "timestamp": time.time(),
    "src": "20.189.173.14",
    "dst": "192.168.1.2",
    "proto": 6,
    "sport": 443,
    "dport": 50697,
    "payload": "Ether / IP / TCP 20.189.173.14:https > 192.168.1.2:50697 A",
    "dur": 0,
    "sbytes": 40,
    "dbytes": 0,
    "sttl": 113,
    "dttl": 113,
    "sload": 0,
    "dload": 0,
    "sloss": 0,
    "dloss": 0,
    "swin": 0,
    "dwin": 0,
    "stcpb": 0,
    "dtcpb": 0,
    "state": "CON"
}

normal_packet_2 = {
    "_id": "66768d35016f267936560c05",
    "timestamp": time.time(),
    "src": "20.189.173.15",
    "dst": "192.168.1.3",
    "proto": 6,
    "sport": 80,
    "dport": 50800,
    "payload": "Ether / IP / TCP 20.189.173.15:http > 192.168.1.3:50800 A",
    "dur": 0,
    "sbytes": 50,
    "dbytes": 0,
    "sttl": 115,
    "dttl": 115,
    "sload": 0,
    "dload": 0,
    "sloss": 0,
    "dloss": 0,
    "swin": 0,
    "dwin": 0,
    "stcpb": 0,
    "dtcpb": 0,
    "state": "CON"
}

malicious_packet = {
    "_id": "66768d35016f267936560c06",
    "timestamp": time.time(),
    "src": "192.168.2.2",
    "dst": "192.168.2.1",
    "proto": 17,
    "sport": 12345,
    "dport": 80,
    "payload": "UDP 192.168.2.2:12345 > 192.168.2.1:80",
    "dur": 10,
    "sbytes": 10000,
    "dbytes": 15000,
    "sttl": 255,
    "dttl": 255,
    "sload": 1000000,
    "dload": 1000000,
    "sloss": 0,
    "dloss": 0,
    "swin": 5840,
    "dwin": 5840,
    "stcpb": 123456789,
    "dtcpb": 987654321,
    "state": "FIN"
}

# Test the specific packets
example_packets = [normal_packet_1, normal_packet_2, malicious_packet]
test_specific_packets(example_packets)

# Output the results
packets_df = pd.DataFrame(packets_collection)
blacklist_df = pd.DataFrame(blacklist_collection)

# Display the dataframes
print("Packets Collection:")
print(packets_df)

print("\nBlacklist Collection:")
print(blacklist_df)

packets_df, blacklist_df
