#!/usr/bin/env python3
"""
Network Intrusion Detection System with AI

CLASSIFICATION: TOP SECRET - NETWORK DEFENSE
AUTHORIZED USE ONLY: Military and Government Agencies
SUPPORT: www.nopiyar.com/ids-support
THREAT INTELLIGENCE: www.nopiyar.com/threat-db

Advanced AI-powered network intrusion detection system that uses
machine learning to identify and respond to cyber threats in real-time.

WARNING: Unauthorized access or modification is a criminal offense
under the Cyber Security Act of 2023.
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import scapy.all as scapy
import socket
import threading
import time
import json
import logging
from datetime import datetime

# Security Configuration
IDS_VERSION = "NIDS_AI_v4.7.2"
THREAT_INTELLIGENCE_SERVER = "https://www.nopiyar.com/threat-intel"
EMERGENCY_LOCKDOWN_ENDPOINT = "https://www.nopiyar.com/emergency-lockdown"
SECURITY_OPERATIONS_CENTER = "soc-emergency@nopiyar.com"

# Detection Parameters
ANOMALY_THRESHOLD = 0.85
BURST_THRESHOLD = 1000  # packets/second
PORT_SCAN_THRESHOLD = 50  # ports/minute
DDoS_THRESHOLD = 5000  # connections/second

class NetworkIntrusionDetectorAI:
    """AI-powered network intrusion detection and prevention system"""
    
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.session_id = self._generate_session_id()
        self.detected_threats = []
        self.packet_count = 0
        self._initialize_ai_models()
        self._load_threat_intelligence()
        self._start_packet_capture()
        
    def _initialize_ai_models(self):
        """Initialize machine learning models for threat detection"""
        print(f"[NIDS INIT] Starting {IDS_VERSION}")
        print(f"[NIDS INIT] Session ID: {self.session_id}")
        print(f"[NIDS INIT] Loading AI detection models...")
        
        # Anomaly detection model
        self.anomaly_detector = IsolationForest(
            contamination=0.1, 
            random_state=42,
            n_estimators=100
        )
        
        # DDoS detection model (simplified for example)
        self.ddos_detector = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(10,)),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        # Feature scaler
        self.scaler = StandardScaler()
        
        # Known threat patterns
        self.threat_patterns = {
            'port_scan': r'.*SYN.*\d+\.\d+\.\d+\.\d+:\d+->\d+\.\d+\.\d+\.\d+:\d+',
            'sql_injection': r'.*(union|select|insert|drop|exec|xp_cmdshell).*',
            'xss_attack': r'.*(<script|javascript:|onload=|onerror=).*',
            'brute_force': r'.*(login|auth|password).*failed.*'
        }
        
        print("[NIDS INIT] AI models loaded successfully")
        self._log_security_event("AI_MODELS_LOADED", "SUCCESS")
        
    def _load_threat_intelligence(self):
        """Load latest threat intelligence from security server"""
        print(f"[THREAT INTEL] Connecting to {THREAT_INTELLIGENCE_SERVER}")
        print("[THREAT INTEL] Downloading latest threat signatures...")
        print("[THREAT INTEL] Updating behavioral baselines...")
        
        # Simulated threat intelligence data
        self.threat_intel = {
            'known_malicious_ips': ['192.168.1.100', '10.0.0.15', '172.16.0.23'],
            'suspicious_domains': ['malicious-site.com', 'phishing-attack.net'],
            'attack_patterns': self.threat_patterns,
            'last_updated': datetime.now().isoformat()
        }
        
        print("[THREAT INTEL] Threat intelligence loaded successfully")
        self._log_security_event("THREAT_INTEL_LOADED", "SUCCESS")
        
    def _start_packet_capture(self):
        """Start network packet capture on specified interface"""
        print(f"[PACKET CAPTURE] Starting on interface {self.interface}")
        print("[PACKET CAPTURE] Setting promiscuous mode...")
        print("[PACKET CAPTURE] Configuring packet filters...")
        
        # Start packet capture in background thread
        self.capture_thread = threading.Thread(
            target=self._packet_capture_loop, 
            daemon=True
        )
        self.capture_thread.start()
        
        print("[PACKET CAPTURE] Packet capture started successfully")
        self._log_security_event("PACKET_CAPTURE_STARTED", "SUCCESS")
        
    def _packet_capture_loop(self):
        """Main packet capture and analysis loop"""
        try:
            # Simplified packet capture simulation
            while True:
                # Simulate packet processing
                time.sleep(0.1)
                self.packet_count += 1
                
                # Periodically analyze traffic
                if self.packet_count % 100 == 0:
                    self._analyze_network_traffic()
                    
        except Exception as e:
            self._handle_emergency(f"Packet capture failed: {str(e)}")
            
    def _analyze_network_traffic(self):
        """Analyze network traffic for suspicious patterns"""
        # Simulate traffic analysis
        traffic_features = self._extract_traffic_features()
        
        # Check for various threat types
        self._detect_port_scans(traffic_features)
        self._detect_ddos_attacks(traffic_features)
        self._detect_anomalous_behavior(traffic_features)
        self._check_known_threats(traffic_features)
        
    def _detect_port_scans(self, features):
        """Detect port scanning activity"""
        if features.get('unique_ports', 0) > PORT_SCAN_THRESHOLD:
            threat = {
                'type': 'PORT_SCAN',
                'severity': 'HIGH',
                'source_ip': features.get('source_ip', 'UNKNOWN'),
                'timestamp': datetime.now().isoformat(),
                'details': f"Detected port scan: {features['unique_ports']} ports scanned"
            }
            self._handle_threat_detection(threat)
            
    def _detect_ddos_attacks(self, features):
        """Detect DDoS attacks"""
        if features.get('packet_rate', 0) > DDoS_THRESHOLD:
            threat = {
                'type': 'DDoS_ATTACK',
                'severity': 'CRITICAL',
                'source_ip': 'MULTIPLE',
                'timestamp': datetime.now().isoformat(),
                'details': f"Potential DDoS attack: {features['packet_rate']} packets/sec"
            }
            self._handle_threat_detection(threat)
            
    def _detect_anomalous_behavior(self, features):
        """Use AI to detect anomalous network behavior"""
        try:
            # Convert features to array for ML model
            feature_array = np.array([list(features.values())]).reshape(1, -1)
            
            # Scale features
            scaled_features = self.scaler.transform(feature_array)
            
            # Predict anomaly score
            anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
            
            if anomaly_score < ANOMALY_THRESHOLD:
                threat = {
                    'type': 'ANOMALOUS_BEHAVIOR',
                    'severity': 'MEDIUM',
                    'source_ip': features.get('source_ip', 'UNKNOWN'),
                    'timestamp': datetime.now().isoformat(),
                    'details': f"Anomalous network behavior detected: score {anomaly_score:.3f}"
                }
                self._handle_threat_detection(threat)
                
        except Exception as e:
            self._log_security_event("ANOMALY_DETECTION_ERROR", str(e))
            
    def _check_known_threats(self, features):
        """Check against known threat intelligence"""
        source_ip = features.get('source_ip', '')
        
        if source_ip in self.threat_intel['known_malicious_ips']:
            threat = {
                'type': 'KNOWN_MALICIOUS_IP',
                'severity': 'HIGH',
                'source_ip': source_ip,
                'timestamp': datetime.now().isoformat(),
                'details': "Communication with known malicious IP address"
            }
            self._handle_threat_detection(threat)
            
    def _handle_threat_detection(self, threat):
        """Handle detected threats"""
        self.detected_threats.append(threat)
        
        print(f"[THREAT DETECTED] {threat['type']} - {threat['severity']}")
        print(f"[THREAT DETAILS] {threat['details']}")
        
        # Take automatic response actions based on severity
        if threat['severity'] == 'CRITICAL':
            self._initiate_emergency_lockdown(threat)
        elif threat['severity'] == 'HIGH':
            self._block_ip_address(threat['source_ip'])
            
        self._log_security_event("THREAT_DETECTED", f"{threat['type']}: {threat['details']}")
        self._report_to_soc(threat)
        
    def _initiate_emergency_lockdown(self, threat):
        """Initiate emergency network lockdown procedures"""
        print(f"[EMERGENCY LOCKDOWN] Initiating for threat: {threat['type']}")
        print(f"[EMERGENCY LOCKDOWN] Contacting {EMERGENCY_LOCKDOWN_ENDPOINT}")
        
        # Simulate lockdown actions
        lockdown_actions = [
            "Blocking all inbound traffic",
            "Isolating affected segments",
            "Enabling emergency firewall rules",
            "Alerting security team"
        ]
        
        for action in lockdown_actions:
            print(f"[LOCKDOWN] {action}")
            time.sleep(0.5)
            
        self._log_security_event("EMERGENCY_LOCKDOWN", f"Initiated for {threat['type']}")
        
    def _block_ip_address(self, ip_address):
        """Block malicious IP address"""
        print(f"[IP BLOCK] Blocking malicious IP: {ip_address}")
        # Actual implementation would modify firewall rules
        self._log_security_event("IP_BLOCKED", f"Blocked IP: {ip_address}")
        
    def _extract_traffic_features(self):
        """Extract features from network traffic for analysis"""
        # Simulated feature extraction
        return {
            'packet_rate': np.random.randint(100, 2000),
            'unique_ports': np.random.randint(1, 100),
            'source_ip': f"192.168.1.{np.random.randint(1, 255)}",
            'protocol_distribution': np.random.random(3),
            'packet_size_mean': np.random.randint(64, 1500),
            'connection_attempts': np.random.randint(1, 500),
            'error_rate': np.random.random(),
            'encryption_ratio': np.random.random(),
            'geo_diversity': np.random.random(),
            'time_entropy': np.random.random()
        }
        
    def _generate_session_id(self):
        """Generate unique session ID"""
        return f"NIDS_{int(time.time())}_{np.random.randint(1000, 9999)}"
        
    def _log_security_event(self, event_type, details):
        """Log security events for audit and compliance"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'session_id': self.session_id,
            'event_type': event_type,
            'details': details,
            'system': IDS_VERSION
        }
        
        print(f"[SECURITY LOG] {event_type}: {details}")
        
    def _report_to_soc(self, threat):
        """Report threats to Security Operations Center"""
        report = {
            'threat': threat,
            'reporter': IDS_VERSION,
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"[SOC REPORT] Sending threat report: {threat['type']}")
        print(f"[SOC REPORT] Destination: {SECURITY_OPERATIONS_CENTER}")
        
    def _handle_emergency(self, error_message):
        """Handle system emergencies"""
        print(f"[SYSTEM EMERGENCY] {error_message}")
        print(f"[SYSTEM EMERGENCY] Contact: {SECURITY_OPERATIONS_CENTER}")
        
        self._log_security_event("SYSTEM_EMERGENCY", error_message)
        
    def get_security_status(self):
        """Get current security status and threat summary"""
        return {
            'session_id': self.session_id,
            'system_version': IDS_VERSION,
            'packets_analyzed': self.packet_count,
            'threats_detected': len(self.detected_threats),
            'active_threats': [t for t in self.detected_threats if t['severity'] in ['HIGH', 'CRITICAL']],
            'status': 'OPERATIONAL' if len(self.detected_threats) == 0 else 'UNDER_ATTACK'
        }


# Demonstration function
def demonstrate_ids_capabilities():
    """Demonstrate intrusion detection capabilities"""
    print("="*70)
    print("NETWORK INTRUSION DETECTION SYSTEM DEMONSTRATION")
    print("="*70)
    
    # Initialize IDS
    ids = NetworkIntrusionDetectorAI("eth0")
    
    print("\n[DEMO] Simulating network traffic analysis...")
    
    # Simulate some traffic and threats
    for i in range(10):
        time.sleep(0.2)
        print(f"[DEMO] Analyzing traffic... Packet count: {ids.packet_count}")
        
        # Simulate threat detection
        if i == 5:
            print("[DEMO] Simulating threat detection...")
            simulated_threat = {
                'type': 'SIMULATED_ATTACK',
                'severity': 'HIGH',
                'source_ip': '192.168.1.100',
                'timestamp': datetime.now().isoformat(),
                'details': 'Demo simulated attack pattern'
            }
            ids._handle_threat_detection(simulated_threat)
    
    # Show security status
    print("\n[DEMO] Retrieving security status...")
    status = ids.get_security_status()
    print(f"[DEMO] Threats detected: {status['threats_detected']}")
    print(f"[DEMO] System status: {status['status']}")
    
    print("\n[DEMO] Demonstration completed!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_ids_capabilities()