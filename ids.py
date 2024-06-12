import subprocess
from scapy.all import sniff, IP, TCP, UDP
import pymongo
import pandas as pd
import pickle
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["ids"]
packets_collection = db["packets"]
blacklist_collection = db["blacklist"]

# Load the trained model and preprocessing tools
with open("best_model.pkl", "rb") as model_file:
    best_clf = pickle.load(model_file)

with open("scaler.pkl", "rb") as scaler_file:
    scaler = pickle.load(scaler_file)

with open("encoder.pkl", "rb") as encoder_file:
    encoder = pickle.load(encoder_file)

# Define the categorical columns used in preprocessing
cat_columns = ["proto", "service", "state"]

# Set to keep track of processed packets
processed_packets = set()

def extract_features(packet):
    features = {
        "dur": 0,  # Duration would need to be computed
        "proto": packet[IP].proto if IP in packet else 0,
        "service": "-",  # Service would need to be determined
        "state": "CON",  # State would need to be determined
        "spkts": 0,  # Packets sent would need to be computed
        "dpkts": 0,  # Packets received would need to be computed
        "sbytes": len(packet[IP].payload) if IP in packet else 0,
        "dbytes": len(packet[IP].payload) if IP in packet else 0,
        "rate": 0,  # Rate would need to be computed
        "sttl": packet[IP].ttl if IP in packet else 0,
        "dttl": 0,  # Destination TTL would need to be computed
        "sload": 0,  # Source load would need to be computed
        "dload": 0,  # Destination load would need to be computed
        "sloss": 0,  # Source loss would need to be computed
        "dloss": 0,  # Destination loss would need to be computed
        "sinpkt": 0,  # Source inter-packet arrival time would need to be computed
        "dinpkt": 0,  # Destination inter-packet arrival time would need to be computed
        "sjit": 0,  # Source jitter would need to be computed
        "djit": 0,  # Destination jitter would need to be computed
        "swin": packet[TCP].window if TCP in packet else 0,
        "stcpb": packet[TCP].seq if TCP in packet else 0,
        "dtcpb": packet[TCP].ack if TCP in packet else 0,
        "dwin": packet[TCP].window if TCP in packet else 0,
        "tcprtt": 0,  # TCP RTT would need to be computed
        "synack": 0,  # SYN-ACK would need to be computed
        "ackdat": 0,  # ACK data would need to be computed
        "smean": 0,  # Source mean packet size would need to be computed
        "dmean": 0,  # Destination mean packet size would need to be computed
        "trans_depth": 0,  # Transaction depth would need to be computed
        "response_body_len": 0,  # Response body length would need to be computed
        "ct_srv_src": 0,  # Connection count to the same source address would need to be computed
        "ct_state_ttl": 0,  # Connection count in the same state would need to be computed
        "ct_dst_ltm": 0,  # Connections to the same destination address would need to be computed
        "ct_src_dport_ltm": 0,  # Connections to the same source port would need to be computed
        "ct_dst_sport_ltm": 0,  # Connections to the same destination port would need to be computed
        "ct_dst_src_ltm": 0,  # Connections between the same source and destination would need to be computed
        "is_ftp_login": 0,  # FTP login status would need to be determined
        "ct_ftp_cmd": 0,  # FTP command count would need to be determined
        "ct_flw_http_mthd": 0,  # HTTP method count would need to be determined
        "ct_src_ltm": 0,  # Connections to the same source would need to be computed
        "ct_srv_dst": 0,  # Connections to the same service would need to be computed
        "is_sm_ips_ports": 0  # IP/port scanning status would need to be determined
    }
    return features

def preprocess_packet(packet_info):
    features = extract_features(packet_info)
    df = pd.DataFrame([features])
    for col in cat_columns:
        if col in df.columns:
            try:
                df[col] = encoder.transform(df[col])
            except ValueError:
                df[col] = -1  # Assign a default value for unseen categories
        else:
            df[col] = -1  # Assign a default value for unseen categories
    X = scaler.transform(df)
    return X

def classify_packet(packet_info):
    X = preprocess_packet(packet_info)
    prediction = best_clf.predict(X)
    
    return prediction

def block_entry(entry):
    ip = entry.get("ip")
    url = entry.get("url")
    
    if ip:
        if blacklist_collection.find_one({"ip": ip}) is None:
                blacklist_collection.insert_one({"url": None})
                blacklist_collection.insert_one({"ip": ip})
           
def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        sport = getattr(packet, 'sport', 0)
        dport = getattr(packet, 'dport', 0)

        packet_id = (src_ip, dst_ip, sport, dport, proto)
        
        if packet_id in processed_packets:
            return

        processed_packets.add(packet_id)
        
        packet_info = {
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "payload": str(packet[IP].payload)
        }
        packets_collection.insert_one(packet_info)

        if classify_packet(packet_info) == "malicious":
            block_entry(dst_ip)



# Start sniffing packets
sniff(prn=packet_handler, store=0)
