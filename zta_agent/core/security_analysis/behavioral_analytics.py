"""
Advanced Behavioral Analytics and Threat Detection
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import logging
from tensorflow.keras import layers, models
import joblib
from threading import Lock

@dataclass
class UserBehaviorProfile:
    """User behavior profile for anomaly detection"""
    typical_access_times: List[int]  # Hour of day (0-23)
    typical_locations: Set[str]  # Country codes
    typical_devices: Set[str]  # Device fingerprints
    typical_resources: Set[str]  # Resource paths
    access_patterns: Dict[str, float]  # Resource:frequency
    average_session_duration: float
    typical_request_rate: float
    last_known_ip: Optional[str]
    risk_score: float = 0.0

@dataclass
class NetworkBehaviorProfile:
    """Network behavior profile for anomaly detection"""
    typical_protocols: Set[str]
    typical_ports: Set[int]
    bandwidth_patterns: Dict[str, float]  # Hour:bandwidth
    connection_patterns: Dict[str, int]  # Hour:connections
    known_peer_ips: Set[str]
    typical_packet_sizes: List[int]
    typical_flow_duration: float
    risk_score: float = 0.0

class BehavioralAnalytics:
    """Advanced behavioral analytics system"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize ML models
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        
        # Initialize neural network for sequence prediction
        self.sequence_model = self._build_sequence_model()
        
        # User and network profiles
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.network_profiles: Dict[str, NetworkBehaviorProfile] = {}
        self.profile_lock = Lock()
        
        # Load pre-trained models if available
        self._load_models()
        
        # Initialize feature extractors
        self.feature_extractors = {
            "temporal": self._extract_temporal_features,
            "spatial": self._extract_spatial_features,
            "volumetric": self._extract_volumetric_features,
            "categorical": self._extract_categorical_features
        }

    def _build_sequence_model(self) -> models.Model:
        """Build neural network for sequence prediction"""
        model = models.Sequential([
            layers.LSTM(64, input_shape=(10, 50)),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dense(16, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])
        model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        return model

    def _load_models(self) -> None:
        """Load pre-trained models"""
        try:
            model_path = self.config["model_path"]
            self.isolation_forest = joblib.load(f"{model_path}/isolation_forest.pkl")
            self.scaler = joblib.load(f"{model_path}/scaler.pkl")
            self.sequence_model.load_weights(f"{model_path}/sequence_model.h5")
        except Exception as e:
            self.logger.warning(f"Could not load pre-trained models: {str(e)}")

    def _save_models(self) -> None:
        """Save trained models"""
        try:
            model_path = self.config["model_path"]
            joblib.dump(self.isolation_forest, f"{model_path}/isolation_forest.pkl")
            joblib.dump(self.scaler, f"{model_path}/scaler.pkl")
            self.sequence_model.save_weights(f"{model_path}/sequence_model.h5")
        except Exception as e:
            self.logger.error(f"Could not save models: {str(e)}")

    def analyze_user_behavior(
        self,
        user_id: str,
        event_data: Dict
    ) -> Tuple[float, List[str]]:
        """
        Analyze user behavior for anomalies
        
        Returns:
            Tuple of (risk_score, anomaly_types)
        """
        with self.profile_lock:
            # Get or create user profile
            profile = self.user_profiles.get(user_id)
            if not profile:
                profile = self._create_user_profile()
                self.user_profiles[user_id] = profile

            # Extract features
            features = self._extract_user_features(event_data, profile)
            
            # Normalize features
            self.scaler.transform([features])
            
            # Get anomaly score from isolation forest
            anomaly_score = self.isolation_forest.score_samples([features])[0]
            
            # Get sequence prediction
            sequence_score = self._predict_sequence(user_id, features)
            
            # Calculate final risk score
            risk_score = self._calculate_risk_score(
                anomaly_score,
                sequence_score,
                profile
            )
            
            # Identify anomaly types
            anomaly_types = self._identify_anomalies(
                event_data,
                profile,
                risk_score
            )
            
            # Update profile
            self._update_user_profile(profile, event_data)
            
            return risk_score, anomaly_types

    def analyze_network_behavior(
        self,
        network_id: str,
        event_data: Dict
    ) -> Tuple[float, List[str]]:
        """
        Analyze network behavior for anomalies
        
        Returns:
            Tuple of (risk_score, anomaly_types)
        """
        with self.profile_lock:
            # Get or create network profile
            profile = self.network_profiles.get(network_id)
            if not profile:
                profile = self._create_network_profile()
                self.network_profiles[network_id] = profile

            # Extract features
            features = self._extract_network_features(event_data, profile)
            
            # Get anomaly score
            anomaly_score = self.isolation_forest.score_samples([features])[0]
            
            # Identify anomalies
            anomaly_types = self._identify_network_anomalies(
                event_data,
                profile,
                anomaly_score
            )
            
            # Update profile
            self._update_network_profile(profile, event_data)
            
            return anomaly_score, anomaly_types

    def _extract_user_features(
        self,
        event_data: Dict,
        profile: UserBehaviorProfile
    ) -> List[float]:
        """Extract numerical features from user event data"""
        features = []
        
        # Time-based features
        hour = datetime.fromtimestamp(event_data["timestamp"]).hour
        features.append(hour / 24.0)  # Normalize to 0-1
        
        # Location-based features
        if "location_info" in event_data:
            loc = event_data["location_info"]
            features.append(1.0 if loc["country"] in profile.typical_locations else 0.0)
            
        # Device-based features
        if "user_agent" in event_data:
            features.append(
                1.0 if event_data["user_agent"] in profile.typical_devices else 0.0
            )
            
        # Resource access features
        if "resource" in event_data:
            features.append(
                1.0 if event_data["resource"] in profile.typical_resources else 0.0
            )
            
        # Request rate features
        current_rate = event_data.get("request_rate", 0)
        features.append(current_rate / profile.typical_request_rate)
        
        return features

    def _extract_network_features(
        self,
        event_data: Dict,
        profile: NetworkBehaviorProfile
    ) -> List[float]:
        """Extract numerical features from network event data"""
        features = []
        
        # Protocol features
        if "protocol" in event_data:
            features.append(
                1.0 if event_data["protocol"] in profile.typical_protocols else 0.0
            )
            
        # Port features
        if "port" in event_data:
            features.append(1.0 if event_data["port"] in profile.typical_ports else 0.0)
            
        # Bandwidth features
        current_bandwidth = event_data.get("bandwidth", 0)
        hour = datetime.fromtimestamp(event_data["timestamp"]).hour
        typical_bandwidth = profile.bandwidth_patterns.get(str(hour), 0)
        features.append(
            current_bandwidth / typical_bandwidth if typical_bandwidth > 0 else 0
        )
        
        # Connection features
        current_connections = event_data.get("connections", 0)
        typical_connections = profile.connection_patterns.get(str(hour), 0)
        features.append(
            current_connections / typical_connections if typical_connections > 0 else 0
        )
        
        return features

    def _predict_sequence(self, user_id: str, features: List[float]) -> float:
        """Predict if current action sequence is anomalous"""
        try:
            # Get recent feature history
            feature_history = self._get_feature_history(user_id)
            if len(feature_history) < 10:
                return 0.5
                
            # Prepare sequence
            sequence = np.array(feature_history[-10:])
            sequence = sequence.reshape((1, 10, len(features)))
            
            # Get prediction
            return float(self.sequence_model.predict(sequence)[0][0])
        except Exception as e:
            self.logger.error(f"Sequence prediction failed: {str(e)}")
            return 0.5

    def _calculate_risk_score(
        self,
        anomaly_score: float,
        sequence_score: float,
        profile: UserBehaviorProfile
    ) -> float:
        """Calculate final risk score"""
        weights = self.config["risk_weights"]
        
        risk_score = (
            weights["anomaly"] * (1 - anomaly_score) +  # Convert to risk
            weights["sequence"] * sequence_score +
            weights["profile"] * profile.risk_score
        )
        
        return min(1.0, max(0.0, risk_score))  # Clamp to 0-1

    def _identify_anomalies(
        self,
        event_data: Dict,
        profile: UserBehaviorProfile,
        risk_score: float
    ) -> List[str]:
        """Identify specific types of anomalies"""
        anomalies = []
        
        # Time-based anomalies
        hour = datetime.fromtimestamp(event_data["timestamp"]).hour
        if hour not in profile.typical_access_times:
            anomalies.append("unusual_access_time")
            
        # Location-based anomalies
        if (
            "location_info" in event_data and
            event_data["location_info"]["country"] not in profile.typical_locations
        ):
            anomalies.append("unusual_location")
            
        # Device-based anomalies
        if (
            "user_agent" in event_data and
            event_data["user_agent"] not in profile.typical_devices
        ):
            anomalies.append("unusual_device")
            
        # Resource access anomalies
        if (
            "resource" in event_data and
            event_data["resource"] not in profile.typical_resources
        ):
            anomalies.append("unusual_resource_access")
            
        # Rate-based anomalies
        if (
            "request_rate" in event_data and
            event_data["request_rate"] > profile.typical_request_rate * 2
        ):
            anomalies.append("high_request_rate")
            
        return anomalies

    def _identify_network_anomalies(
        self,
        event_data: Dict,
        profile: NetworkBehaviorProfile,
        anomaly_score: float
    ) -> List[str]:
        """Identify specific types of network anomalies"""
        anomalies = []
        
        # Protocol anomalies
        if (
            "protocol" in event_data and
            event_data["protocol"] not in profile.typical_protocols
        ):
            anomalies.append("unusual_protocol")
            
        # Port anomalies
        if "port" in event_data and event_data["port"] not in profile.typical_ports:
            anomalies.append("unusual_port")
            
        # Bandwidth anomalies
        if "bandwidth" in event_data:
            hour = datetime.fromtimestamp(event_data["timestamp"]).hour
            typical = profile.bandwidth_patterns.get(str(hour), 0)
            if event_data["bandwidth"] > typical * 2:
                anomalies.append("high_bandwidth")
                
        # Connection anomalies
        if "connections" in event_data:
            hour = datetime.fromtimestamp(event_data["timestamp"]).hour
            typical = profile.connection_patterns.get(str(hour), 0)
            if event_data["connections"] > typical * 2:
                anomalies.append("high_connections")
                
        return anomalies

    def _create_user_profile(self) -> UserBehaviorProfile:
        """Create new user behavior profile"""
        return UserBehaviorProfile(
            typical_access_times=[],
            typical_locations=set(),
            typical_devices=set(),
            typical_resources=set(),
            access_patterns={},
            average_session_duration=0.0,
            typical_request_rate=0.0,
            last_known_ip=None
        )

    def _create_network_profile(self) -> NetworkBehaviorProfile:
        """Create new network behavior profile"""
        return NetworkBehaviorProfile(
            typical_protocols=set(),
            typical_ports=set(),
            bandwidth_patterns={},
            connection_patterns={},
            known_peer_ips=set(),
            typical_packet_sizes=[],
            typical_flow_duration=0.0
        )

    def _update_user_profile(
        self,
        profile: UserBehaviorProfile,
        event_data: Dict
    ) -> None:
        """Update user behavior profile with new data"""
        # Update access times
        hour = datetime.fromtimestamp(event_data["timestamp"]).hour
        if hour not in profile.typical_access_times:
            profile.typical_access_times.append(hour)
            
        # Update locations
        if "location_info" in event_data:
            profile.typical_locations.add(event_data["location_info"]["country"])
            
        # Update devices
        if "user_agent" in event_data:
            profile.typical_devices.add(event_data["user_agent"])
            
        # Update resources
        if "resource" in event_data:
            profile.typical_resources.add(event_data["resource"])
            profile.access_patterns[event_data["resource"]] = (
                profile.access_patterns.get(event_data["resource"], 0) + 1
            )
            
        # Update request rate
        if "request_rate" in event_data:
            profile.typical_request_rate = (
                0.9 * profile.typical_request_rate +
                0.1 * event_data["request_rate"]
            )
            
        # Update IP
        if "source_ip" in event_data:
            profile.last_known_ip = event_data["source_ip"]

    def _update_network_profile(
        self,
        profile: NetworkBehaviorProfile,
        event_data: Dict
    ) -> None:
        """Update network behavior profile with new data"""
        # Update protocols
        if "protocol" in event_data:
            profile.typical_protocols.add(event_data["protocol"])
            
        # Update ports
        if "port" in event_data:
            profile.typical_ports.add(event_data["port"])
            
        # Update bandwidth patterns
        if "bandwidth" in event_data:
            hour = str(datetime.fromtimestamp(event_data["timestamp"]).hour)
            current = profile.bandwidth_patterns.get(hour, 0)
            profile.bandwidth_patterns[hour] = 0.9 * current + 0.1 * event_data["bandwidth"]
            
        # Update connection patterns
        if "connections" in event_data:
            hour = str(datetime.fromtimestamp(event_data["timestamp"]).hour)
            current = profile.connection_patterns.get(hour, 0)
            profile.connection_patterns[hour] = int(
                0.9 * current + 0.1 * event_data["connections"]
            )
            
        # Update peer IPs
        if "peer_ip" in event_data:
            profile.known_peer_ips.add(event_data["peer_ip"])
            
        # Update packet sizes
        if "packet_size" in event_data:
            profile.typical_packet_sizes.append(event_data["packet_size"])
            if len(profile.typical_packet_sizes) > 1000:
                profile.typical_packet_sizes = profile.typical_packet_sizes[-1000:]

    def _get_feature_history(self, user_id: str) -> List[List[float]]:
        """Get recent feature history for a user"""
        # This would typically be stored in a database or cache
        # For now, we'll return an empty list
        return []

    def train_models(self, training_data: List[Dict]) -> None:
        """Train ML models on historical data"""
        try:
            # Prepare features
            features = []
            for event in training_data:
                user_features = self._extract_user_features(
                    event,
                    self._create_user_profile()
                )
                network_features = self._extract_network_features(
                    event,
                    self._create_network_profile()
                )
                features.append(user_features + network_features)
                
            # Train isolation forest
            self.isolation_forest.fit(features)
            
            # Train scaler
            self.scaler.fit(features)
            
            # Save models
            self._save_models()
            
        except Exception as e:
            self.logger.error(f"Model training failed: {str(e)}")

    def get_user_profile(self, user_id: str) -> Optional[UserBehaviorProfile]:
        """Get user behavior profile"""
        return self.user_profiles.get(user_id)

    def get_network_profile(self, network_id: str) -> Optional[NetworkBehaviorProfile]:
        """Get network behavior profile"""
        return self.network_profiles.get(network_id)
