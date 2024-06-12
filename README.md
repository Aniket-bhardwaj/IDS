# IDS
Intrusion Detection System (IDS) with Machine Learning and MongoDB

# Project Report: Intrusion Detection System (IDS) with Machine Learning and MongoDB

## Table of Contents
1. Introduction
2. Objectives
3. System Components
4. Detailed Workflow
5. Implementation
6. Evaluation and Testing
7. Conclusion
8. Future Work
9. References
10. Important Links
    
## 1. Introduction

In the modern digital landscape, network security is of paramount importance. Intrusion Detection Systems (IDS) play a crucial role in monitoring network traffic, identifying suspicious activities, and taking action to prevent potential threats. This project involves the creation of an IDS that leverages machine learning (ML) for real-time packet classification and uses MongoDB for logging and analysis.

## 2. Objectives

The primary objectives of this project are:
- To develop an IDS capable of real-time monitoring of network traffic.
- To use machine learning for classifying network packets as benign or malicious.
- To block malicious connections using firewall rules.
- To log all network activities and blocked connections in a MongoDB database.
- To ensure the system runs with the necessary administrative privileges on Windows.

## 3. System Components

The IDS comprises the following key components:
- **Packet Sniffing**: Captures real-time network traffic.
- **Feature Extraction**: Extracts relevant attributes from each packet.
- **Preprocessing**: Transforms extracted features for ML model input.
- **Classification**: Uses a pre-trained ML model to classify packets.
- **Blocking Malicious Traffic**: Blocks IP addresses of malicious packets.
- **Logging**: Stores packet and block information in MongoDB.
- **Admin Privileges Handling**: Ensures the script runs with administrative privileges.

## 4. Detailed Workflow

### 4.1 Packet Sniffing
The system uses the `scapy` library to sniff network packets in real-time. Each captured packet is processed to extract relevant features.

### 4.2 Feature Extraction
Relevant features such as source IP, destination IP, protocol, and ports are extracted from each packet. If certain attributes are missing, default values are used to ensure consistency.

### 4.3 Preprocessing
The extracted features are transformed using encoding and scaling to match the format used during the ML model training.

### 4.4 Classification
The preprocessed features are fed into a pre-trained ML model, which classifies the packets as benign or malicious. The model was trained on a labeled dataset with similar features.

### 4.5 Blocking Malicious Traffic
If a packet is classified as malicious, the system blocks the corresponding IP address using `netsh` commands on Windows. For URLs, it simulates the blocking process.

### 4.6 Logging
All packets and blocked IPs/URLs are logged in MongoDB. The `packets` collection stores detailed packet information, while the `blacklist` collection keeps track of blocked entries.

### 4.7 Admin Privileges Handling
The script checks if it is running with administrative privileges. If not, it relaunches itself with elevated privileges to execute the necessary firewall commands.

## 5. Implementation

### 5.1 Environment Setup
- **Python**: The script is written in Python and requires `scapy`, `pymongo`, and other dependencies.
- **MongoDB**: A MongoDB instance is used to store logs.
- **Windows**: The system runs on Windows and uses `netsh` for firewall management.

### 5.2 Pre-trained Machine Learning Model
A machine learning model is trained using a labeled dataset, such as UNSW-NB15. The model is saved and loaded during the IDS runtime for packet classification.

### 5.3 Administrative Privileges
The script includes a mechanism to check and request administrative privileges if necessary. This ensures that the `netsh` commands are executed successfully.

## 6. Evaluation and Testing

The IDS was tested in a controlled environment using a mix of benign and malicious traffic. The evaluation metrics included:
- **Accuracy**: The proportion of correctly classified packets.
- **Precision and Recall**: The effectiveness of the system in identifying malicious packets.
- **System Performance**: The impact on network latency and resource usage.

## 7. Conclusion

This project successfully developed an IDS using machine learning and MongoDB. The system effectively captures, processes, and classifies network packets in real-time, blocking malicious connections and logging activities for further analysis. The implementation ensures the necessary administrative privileges for firewall management on Windows.

## 8. Future Work

Future improvements and extensions of the project may include:
- **Enhanced Feature Extraction**: Adding more features for better classification accuracy.
- **Advanced Blocking Mechanisms**: Implementing real URL blocking using proxy servers or specialized firewalls.
- **Scalability**: Optimizing the system for larger networks and higher traffic volumes.
- **Real-time Alerts**: Integrating alert systems to notify administrators of potential threats.

## 9. References

- UNSW-NB15 Dataset: A comprehensive dataset for network intrusion detection.
- Scapy Documentation: Official documentation for the `scapy` library.
- MongoDB Documentation: Official MongoDB documentation for database management.
- Python Official Documentation: Comprehensive guide to Python programming.

## 10. Links
dataset : https://research.unsw.edu.au/projects/unsw-nb15-dataset
MongoDB Create a DM named ids and two collections name Blacklist and Packets to make this work update the database link in code too 


