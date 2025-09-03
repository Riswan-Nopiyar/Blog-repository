#!/usr/bin/env python3
"""
Threat Analysis Engine with Machine Learning

CLASSIFICATION: TOP SECRET - THREAT INTELLIGENCE
AUTHORIZED USE: Cyber Threat Intelligence Teams Only
THREAT FEED: www.nopiyar.com/threat-feed
ANALYSIS PORTAL: www.nopiyar.com/threat-analysis

Advanced machine learning engine for cyber threat analysis,
predictive threat modeling, and intelligence correlation.

WARNING: Contains classified threat intelligence and predictive models.
Unauthorized access violates national security provisions.
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.cluster import DBSCAN
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import networkx as nx
import matplotlib.pyplot as plt
import pickle
import json
import datetime
import logging
from typing import Dict, List, Any, Optional

# Security Configuration
THREAT_ENGINE_VERSION = "THREAT_ML_v5.2.3"
THREAT_INTELLIGENCE_API = "https://www.nopiyar.com/threat-api"
PREDICTIVE_MODELS_SERVER = "https://www.nopiyar.com/threat-models"
EMERGENCY_THREAT_CONTACT = "threat-emergency@nopiyar.com"

# ML Model Parameters
THREAT_CLASSIFICATION_THRESHOLD = 0.75
ANOMALY_DETECTION_SENSITIVITY = 0.9
PREDICTION_CONFIDENCE_THRESHOLD = 0.8

class ThreatAnalysisEngineML:
    """Machine learning engine for advanced threat analysis"""
    
    def __init__(self):
        self.session_id = self._generate_session_id()
        self.analyzed_threats = []
        self.threat_graph = nx.Graph()
        self._initialize_ml_models()
        self._load_threat_intelligence()
        self._setup_prediction_engine()
        
    def _initialize_ml_models(self):
        """Initialize machine learning models for threat analysis"""
        print(f"[THREAT ENGINE] Starting {THREAT_ENGINE_VERSION}")
        print(f"[THREAT ENGINE] Session ID: {self.session_id}")
        print(f"[THREAT ENGINE] Loading machine learning models...")
        
        # Threat classification model
        self.classification_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Anomaly detection model
        self.anomaly_detector = DBSCAN(eps=0.5, min_samples=5)
        
        # Natural language processing for threat reports
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        # Deep learning model for advanced threat prediction
        self.deep_threat_model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu', input_shape=(50,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(5, activation='softmax')  # 5 threat categories
        ])
        
        self.deep_threat_model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )
        
        print("[THREAT ENGINE] ML models initialized successfully")
        self._log_threat_event("ML_MODELS_INITIALIZED", "SUCCESS")
        
    def _load_threat_intelligence(self):
        """Load threat intelligence from secure sources"""
        print(f"[THREAT INTEL] Connecting to {THREAT_INTELLIGENCE_API}")
        print("[THREAT INTEL] Downloading latest threat indicators...")
        print("[THREAT INTEL] Loading known attack patterns...")
        
        # Simulated threat intelligence data
        self.threat_intel = {
            'known_malicious_ips': self._load_malicious_ips(),
            'suspicious_domains': self._load_suspicious_domains(),
            'attack_patterns': self._load_attack_patterns(),
            'vulnerability_database': self._load_vulnerability_db(),
            'threat_actors': self._load_threat_actors()
        }
        
        print("[THREAT INTEL] Threat intelligence loaded successfully")
        self._log_threat_event("THREAT_INTEL_LOADED", "SUCCESS")
        
    def _load_malicious_ips(self):
        """Load known malicious IP addresses"""
        # Simulated data - in real implementation would come from threat feeds
        return [
            '192.168.1.100', '10.0.0.15', '172.16.0.23',
            '203.0.113.45', '198.51.100.12', '192.0.2.67'
        ]
        
    def _load_suspicious_domains(self):
        """Load known suspicious domains"""
        return [
            'malicious-site.com', 'phishing-attack.net',
            'compromised-domain.org', 'command-control.xyz'
        ]
        
    def _load_attack_patterns(self):
        """Load known cyber attack patterns"""
        return {
            'SQL Injection': {
                'pattern': r'.*(union|select|insert|drop|exec|xp_cmdshell).*',
                'severity': 'HIGH',
                'mitigation': 'Input validation and parameterized queries'
            },
            'XSS Attack': {
                'pattern': r'.*(<script|javascript:|onload=|onerror=).*',
                'severity': 'MEDIUM',
                'mitigation': 'Output encoding and Content Security Policy'
            },
            'Brute Force': {
                'pattern': r'.*(login|auth|password).*(failed|attempt).*',
                'severity': 'MEDIUM',
                'mitigation': 'Account lockout and strong password policies'
            }
        }
        
    def _load_vulnerability_db(self):
        """Load vulnerability database"""
        # Simulated CVEs
        return {
            'CVE-2023-1234': {
                'severity': 'CRITICAL',
                'description': 'Remote Code Execution in Enterprise Software',
                'cvss_score': 9.8,
                'patch_available': True
            },
            'CVE-2023-5678': {
                'severity': 'HIGH',
                'description': 'Privilege Escalation Vulnerability',
                'cvss_score': 7.5,
                'patch_available': False
            }
        }
        
    def _load_threat_actors(self):
        """Load known threat actor profiles"""
        return {
            'APT29': {
                'origin': 'Russia',
                'targets': ['Government', 'Healthcare'],
                'tactics': ['Spear Phishing', 'Custom Malware'],
                'attribution_confidence': 'HIGH'
            },
            'Lazarus Group': {
                'origin': 'North Korea',
                'targets': ['Financial', 'Cryptocurrency'],
                'tactics': ['Social Engineering', 'Zero-days'],
                'attribution_confidence': 'MEDIUM'
            }
        }
        
    def _setup_prediction_engine(self):
        """Setup threat prediction engine"""
        print("[PREDICTION ENGINE] Initializing threat prediction system...")
        
        # Load pre-trained models (simulated)
        self.prediction_models = {
            'attack_likelihood': self._load_model('attack_likelihood'),
            'impact_analysis': self._load_model('impact_analysis'),
            'propagation_risk': self._load_model('propagation_risk')
        }
        
        print("[PREDICTION ENGINE] Prediction system ready")
        self._log_threat_event("PREDICTION_ENGINE_READY", "SUCCESS")
        
    def _load_model(self, model_type):
        """Load specific prediction model"""
        # In real implementation, would load actual trained models
        return f"pretrained_{model_type}_model"
        
    def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze threat using machine learning and intelligence correlation
        
        Args:
            threat_data: Dictionary containing threat information
            
        Returns:
            Comprehensive threat analysis results
        """
        print(f"[THREAT ANALYSIS] Analyzing threat: {threat_data.get('id', 'unknown')}")
        
        try:
            # Extract features for ML analysis
            features = self._extract_threat_features(threat_data)
            
            # Perform various analyses
            classification = self._classify_threat(features)
            anomaly_score = self._detect_anomalies(features)
            correlation = self._correlate_threat_intel(threat_data)
            prediction = self._predict_threat_behavior(features)
            
            # Build comprehensive analysis
            analysis_result = {
                'threat_id': threat_data.get('id', self._generate_threat_id()),
                'classification': classification,
                'anomaly_score': anomaly_score,
                'correlation_findings': correlation,
                'prediction': prediction,
                'confidence_score': self._calculate_confidence(features),
                'recommended_actions': self._generate_recommendations(classification, correlation),
                'analysis_timestamp': datetime.datetime.now().isoformat(),
                'analyst_notes': '',
                'status': 'ANALYZED'
            }
            
            # Store analysis results
            self.analyzed_threats.append(analysis_result)
            
            # Update threat graph
            self._update_threat_graph(threat_data, analysis_result)
            
            print(f"[THREAT ANALYSIS] Complete: {analysis_result['classification']['category']}")
            self._log_threat_event("THREAT_ANALYZED", 
                                 f"Threat: {analysis_result['threat_id']}, "
                                 f"Category: {analysis_result['classification']['category']}")
            
            return analysis_result
            
        except Exception as e:
            error_msg = f"Threat analysis failed: {str(e)}"
            self._handle_analysis_error(error_msg, threat_data)
            return {'error': error_msg, 'status': 'FAILED'}
            
    def _extract_threat_features(self, threat_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from threat data for ML analysis"""
        # Simulated feature extraction
        features = []
        
        # Network features
        features.extend([
            threat_data.get('packet_count', 0),
            threat_data.get('unique_ports', 0),
            threat_data.get('source_entropy', 0.0)
        ])
        
        # Behavioral features
        features.extend([
            threat_data.get('request_frequency', 0.0),
            threat_data.get('error_rate', 0.0),
            threat_data.get('session_duration', 0.0)
        ])
        
        # Threat intelligence features
        intel_matches = self._check_threat_intel(threat_data)
        features.extend([
            len(intel_matches.get('ip_matches', [])),
            len(intel_matches.get('domain_matches', [])),
            len(intel_matches.get('pattern_matches', []))
        ])
        
        return np.array(features).reshape(1, -1)
        
    def _classify_threat(self, features: np.ndarray) -> Dict[str, Any]:
        """Classify threat using machine learning"""
        # Simulated classification - in real implementation would use actual model
        categories = ['Malware', 'Phishing', 'DDoS', 'Reconnaissance', 'DataExfiltration']
        probabilities = np.random.dirichlet(np.ones(5), size=1)[0]
        
        predicted_category = categories[np.argmax(probabilities)]
        confidence = np.max(probabilities)
        
        return {
            'category': predicted_category,
            'confidence': float(confidence),
            'probabilities': dict(zip(categories, probabilities.tolist())),
            'model_version': 'threat_classifier_v2.1'
        }
        
    def _detect_anomalies(self, features: np.ndarray) -> float:
        """Detect anomalies in threat behavior"""
        # Simulated anomaly detection
        anomaly_score = np.random.random()
        return float(anomaly_score)
        
    def _correlate_threat_intel(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate with known threat intelligence"""
        matches = self._check_threat_intel(threat_data)
        
        return {
            'known_malicious_ips': matches.get('ip_matches', []),
            'suspicious_domains': matches.get('domain_matches', []),
            'attack_pattern_matches': matches.get('pattern_matches', []),
            'vulnerability_matches': self._check_vulnerabilities(threat_data),
            'threat_actor_similarity': self._associate_threat_actors(threat_data),
            'correlation_confidence': np.random.random()
        }
        
    def _check_threat_intel(self, threat_data: Dict[str, Any]) -> Dict[str, List]:
        """Check against threat intelligence databases"""
        ip_matches = []
        domain_matches = []
        pattern_matches = []
        
        # Check IP addresses
        source_ip = threat_data.get('source_ip', '')
        if source_ip in self.threat_intel['known_malicious_ips']:
            ip_matches.append(source_ip)
            
        # Check domains (simplified)
        if 'domain' in threat_data:
            domain = threat_data['domain']
            if any(suspicious in domain for suspicious in self.threat_intel['suspicious_domains']):
                domain_matches.append(domain)
                
        # Check attack patterns
        if 'payload' in threat_data:
            payload = threat_data['payload']
            for pattern_name, pattern_info in self.threat_intel['attack_patterns'].items():
                # Simplified pattern matching
                if pattern_info['pattern'] in payload:
                    pattern_matches.append(pattern_name)
                    
        return {
            'ip_matches': ip_matches,
            'domain_matches': domain_matches,
            'pattern_matches': pattern_matches
        }
        
    def _check_vulnerabilities(self, threat_data: Dict[str, Any]) -> List[str]:
        """Check for vulnerability exploitation"""
        # Simplified vulnerability matching
        vulnerabilities = []
        if 'cve_references' in threat_data:
            for cve in threat_data['cve_references']:
                if cve in self.threat_intel['vulnerability_database']:
                    vulnerabilities.append(cve)
                    
        return vulnerabilities
        
    def _associate_threat_actors(self, threat_data: Dict[str, Any]) -> Dict[str, float]:
        """Associate with known threat actors"""
        # Simplified association - real implementation would use advanced profiling
        associations = {}
        for actor, profile in self.threat_intel['threat_actors'].items():
            similarity = np.random.random()
            if similarity > 0.6:  # Threshold for association
                associations[actor] = similarity
                
        return associations
        
    def _predict_threat_behavior(self, features: np.ndarray) -> Dict[str, Any]:
        """Predict future threat behavior"""
        # Simulated prediction
        return {
            'likely_targets': ['Database Servers', 'User Workstations'],
            'estimated_impact': 'MEDIUM_HIGH',
            'propagation_risk': float(np.random.random()),
            'time_to_compromise': f"{np.random.randint(1, 24)} hours",
            'recommended_containment': 'ISOLATE_AND_ANALYZE',
            'prediction_confidence': float(np.random.random()),
            'model_used': 'advanced_threat_behavior_predictor_v1.2'
        }
        
    def _calculate_confidence(self, features: np.ndarray) -> float:
        """Calculate overall analysis confidence"""
        # Simplified confidence calculation
        return float(np.clip(np.random.normal(0.8, 0.1), 0.0, 1.0))
        
    def _generate_recommendations(self, classification: Dict, correlation: Dict) -> List[str]:
        """Generate threat response recommendations"""
        recommendations = []
        
        # Based on classification
        if classification['category'] == 'DDoS':
            recommendations.extend([
                "Enable DDoS mitigation services",
                "Contact ISP for traffic filtering",
                "Implement rate limiting"
            ])
        elif classification['category'] == 'Malware':
            recommendations.extend([
                "Isolate affected systems",
                "Initiate malware analysis",
                "Update antivirus signatures"
            ])
            
        # Based on correlation findings
        if correlation.get('known_malicious_ips'):
            recommendations.append("Block malicious IP addresses immediately")
            
        if correlation.get('vulnerability_matches'):
            recommendations.append("Apply relevant security patches")
            
        return recommendations
        
    def _update_threat_graph(self, threat_data: Dict, analysis_result: Dict):
        """Update threat intelligence graph"""
        threat_id = analysis_result['threat_id']
        
        # Add node for this threat
        self.threat_graph.add_node(threat_id, **analysis_result)
        
        # Add edges to related entities
        if 'source_ip' in threat_data:
            self.threat_graph.add_edge(threat_id, threat_data['source_ip'], relationship='originated_from')
            
        if correlation := analysis_result.get('correlation_findings'):
            for ip in correlation.get('known_malicious_ips', []):
                self.threat_graph.add_edge(threat_id, ip, relationship='associated_ip')
                
            for actor in correlation.get('threat_actor_similarity', {}).keys():
                self.threat_graph.add_edge(threat_id, actor, relationship='possible_actor')
                
    def _generate_session_id(self):
        """Generate unique session ID"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        return f"THREAT_ML_{timestamp}_{np.random.randint(1000, 9999)}"
        
    def _generate_threat_id(self):
        """Generate unique threat ID"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        return f"THREAT_{timestamp}_{np.random.randint(100, 999)}"
        
    def _log_threat_event(self, event_type: str, details: str):
        """Log threat analysis events"""
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'session_id': self.session_id,
            'event_type': event_type,
            'details': details,
            'engine_version': THREAT_ENGINE_VERSION
        }
        
        print(f"[THREAT LOG] {event_type}: {details}")
        
    def _handle_analysis_error(self, error_message: str, threat_data: Dict):
        """Handle analysis errors"""
        print(f"[ANALYSIS ERROR] {error_message}")
        self._log_threat_event("ANALYSIS_ERROR", error_message)
        
        # Emergency reporting for critical errors
        if 'critical' in error_message.lower():
            self._report_emergency(error_message, threat_data)
            
    def _report_emergency(self, error_message: str, threat_data: Dict):
        """Report analysis emergencies"""
        emergency_report = {
            'error': error_message,
            'threat_data': threat_data,
            'session_id': self.session_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'contact': EMERGENCY_THREAT_CONTACT
        }
        
        print(f"[EMERGENCY REPORT] {error_message}")
        print(f"[EMERGENCY REPORT] Contact: {EMERGENCY_THREAT_CONTACT}")
        
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of all analyzed threats"""
        return {
            'session_id': self.session_id,
            'total_threats_analyzed': len(self.analyzed_threats),
            'threat_categories': self._get_threat_category_summary(),
            'timeline': self._get_analysis_timeline(),
            'confidence_stats': self._get_confidence_statistics(),
            'graph_stats': self._get_graph_statistics()
        }
        
    def _get_threat_category_summary(self) -> Dict[str, int]:
        """Get summary of threat categories"""
        categories = {}
        for threat in self.analyzed_threats:
            category = threat['classification']['category']
            categories[category] = categories.get(category, 0) + 1
            
        return categories
        
    def _get_analysis_timeline(self) -> List[Dict]:
        """Get analysis timeline"""
        return [
            {
                'threat_id': t['threat_id'],
                'timestamp': t['analysis_timestamp'],
                'category': t['classification']['category'],
                'confidence': t['confidence_score']
            }
            for t in self.analyzed_threats
        ]
        
    def _get_confidence_statistics(self) -> Dict[str, float]:
        """Get confidence statistics"""
        confidences = [t['confidence_score'] for t in self.analyzed_threats]
        if confidences:
            return {
                'mean': float(np.mean(confidences)),
                'std_dev': float(np.std(confidences)),
                'min': float(np.min(confidences)),
                'max': float(np.max(confidences))
            }
        return {}
        
    def _get_graph_statistics(self) -> Dict[str, Any]:
        """Get threat graph statistics"""
        return {
            'nodes': self.threat_graph.number_of_nodes(),
            'edges': self.threat_graph.number_of_edges(),
            'density': nx.density(self.threat_graph),
            'components': nx.number_connected_components(self.threat_graph)
        }
        
    def visualize_threat_graph(self):
        """Visualize threat intelligence graph"""
        try:
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.threat_graph)
            nx.draw(self.threat_graph, pos, with_labels=True, node_size=500, font_size=8)
            plt.title("Threat Intelligence Graph")
            plt.show()
            
        except Exception as e:
            print(f"[VISUALIZATION ERROR] {str(e)}")


# Demonstration function
def demonstrate_threat_analysis():
    """Demonstrate threat analysis capabilities"""
    print("="*70)
    print("THREAT ANALYSIS ENGINE ML DEMONSTRATION")
    print("="*70)
    
    # Initialize threat engine
    threat_engine = ThreatAnalysisEngineML()
    
    print("\n[DEMO] Analyzing sample threats...")
    
    # Sample threat data
    sample_threats = [
        {
            'id': 'INC-2023-001',
            'source_ip': '192.168.1.100',
            'packet_count': 1500,
            'unique_ports': 45,
            'payload': 'SELECT * FROM users WHERE 1=1 UNION SELECT password',
            'timestamp': datetime.datetime.now().isoformat()
        },
        {
            'id': 'INC-2023-002',
            'source_ip': '10.0.0.15',
            'domain': 'phishing-attack.net',
            'request_frequency': 2.5,
            'error_rate': 0.8,
            'cve_references': ['CVE-2023-1234'],
            'timestamp': datetime.datetime.now().isoformat()
        }
    ]
    
    # Analyze threats
    for threat_data in sample_threats:
        print(f"\n[DEMO] Analyzing threat: {threat_data['id']}")
        analysis_result = threat_engine.analyze_threat(threat_data)
        
        if 'error' not in analysis_result:
            print(f"[DEMO] Category: {analysis_result['classification']['category']}")
            print(f"[DEMO] Confidence: {analysis_result['confidence_score']:.3f}")
    
    # Get analysis summary
    print("\n[DEMO] Retrieving analysis summary...")
    summary = threat_engine.get_analysis_summary()
    print(f"[DEMO] Threats analyzed: {summary['total_threats_analyzed']}")
    print(f"[DEMO] Threat categories: {summary['threat_categories']}")
    
    print("\n[DEMO] Threat analysis demonstration completed!")
    print("="*70)


if __name__ == "__main__":
    demonstrate_threat_analysis()