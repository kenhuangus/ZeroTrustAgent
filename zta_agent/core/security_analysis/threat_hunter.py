"""
Advanced Threat Hunting and MITRE ATT&CK Integration
"""
import os
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import requests
import json
import logging
from datetime import datetime
import re
import yaml
from threading import Lock

@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    type: str  # file, network, process, registry
    value: str
    confidence: float
    severity: str
    tags: List[str]
    mitre_techniques: List[str]
    first_seen: datetime
    last_seen: datetime
    source: str
    context: Dict

@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique data structure"""
    technique_id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    detection: str
    mitigation: str
    data_sources: List[str]

class ThreatHunter:
    """Advanced threat hunting system with MITRE ATT&CK integration"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize MITRE ATT&CK data
        self.mitre_techniques: Dict[str, MITRETechnique] = {}
        self.mitre_tactics: Dict[str, str] = {}
        self._load_mitre_data()
        
        # Initialize threat indicators
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.indicator_lock = Lock()
        
        # Load detection rules
        self.detection_rules = self._load_detection_rules()
        
        # Initialize hunting patterns
        self.hunting_patterns = self._load_hunting_patterns()
        
        # Initialize IOC feeds
        self.ioc_feeds = self._initialize_ioc_feeds()
        
        # Cached threat intelligence
        self.threat_intel_cache: Dict[str, Dict] = {}
        self.cache_lock = Lock()

    def _load_mitre_data(self) -> None:
        """Load MITRE ATT&CK framework data"""
        try:
            # Load from local cache if available
            cache_file = self.config["mitre_cache_file"]
            with open(cache_file, 'r') as f:
                data = json.load(f)
                
            for technique in data["techniques"]:
                self.mitre_techniques[technique["technique_id"]] = MITRETechnique(
                    technique_id=technique["technique_id"],
                    name=technique["name"],
                    description=technique["description"],
                    tactics=technique["tactics"],
                    platforms=technique["platforms"],
                    detection=technique["detection"],
                    mitigation=technique["mitigation"],
                    data_sources=technique["data_sources"]
                )
                
            for tactic in data["tactics"]:
                self.mitre_tactics[tactic["tactic_id"]] = tactic["name"]
                
        except FileNotFoundError:
            # Download from MITRE ATT&CK API
            self._download_mitre_data()

    def _download_mitre_data(self) -> None:
        """Download MITRE ATT&CK data from API"""
        try:
            # Download enterprise ATT&CK data
            response = requests.get(
                "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            )
            data = response.json()
            
            # Parse and store techniques
            techniques = []
            for obj in data["objects"]:
                if obj["type"] == "attack-pattern":
                    technique = {
                        "technique_id": obj["external_references"][0]["external_id"],
                        "name": obj["name"],
                        "description": obj["description"],
                        "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                        "platforms": obj.get("x_mitre_platforms", []),
                        "detection": obj.get("x_mitre_detection", ""),
                        "mitigation": obj.get("x_mitre_mitigation", ""),
                        "data_sources": obj.get("x_mitre_data_sources", [])
                    }
                    techniques.append(technique)
                    
            # Save to cache
            cache_data = {
                "techniques": techniques,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            with open(self.config["mitre_cache_file"], 'w') as f:
                json.dump(cache_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to download MITRE data: {str(e)}")

    def _load_detection_rules(self) -> Dict:
        """Load YARA and Sigma rules"""
        rules = {
            "yara": [],
            "sigma": [],
            "custom": []
        }
        
        try:
            # Load YARA rules
            yara_path = self.config["yara_rules_path"]
            for file in os.listdir(yara_path):
                if file.endswith('.yar'):
                    with open(os.path.join(yara_path, file), 'r') as f:
                        rules["yara"].append(f.read())
                        
            # Load Sigma rules
            sigma_path = self.config["sigma_rules_path"]
            for file in os.listdir(sigma_path):
                if file.endswith('.yml'):
                    with open(os.path.join(sigma_path, file), 'r') as f:
                        rules["sigma"].append(yaml.safe_load(f))
                        
            # Load custom rules
            custom_path = self.config["custom_rules_path"]
            for file in os.listdir(custom_path):
                if file.endswith('.json'):
                    with open(os.path.join(custom_path, file), 'r') as f:
                        rules["custom"].append(json.load(f))
                        
        except Exception as e:
            self.logger.error(f"Failed to load detection rules: {str(e)}")
            
        return rules

    def _load_hunting_patterns(self) -> Dict:
        """Load threat hunting patterns"""
        try:
            with open(self.config["hunting_patterns_file"], 'r') as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load hunting patterns: {str(e)}")
            return {}

    def _initialize_ioc_feeds(self) -> Dict:
        """Initialize threat intelligence feeds"""
        feeds = {}
        
        for feed_config in self.config["ioc_feeds"]:
            try:
                feed_type = feed_config["type"]
                if feed_type == "alienvault":
                    feeds["alienvault"] = self._setup_alienvault_feed(feed_config)
                elif feed_type == "misp":
                    feeds["misp"] = self._setup_misp_feed(feed_config)
                elif feed_type == "custom":
                    feeds[feed_config["name"]] = self._setup_custom_feed(feed_config)
            except Exception as e:
                self.logger.error(f"Failed to initialize feed {feed_type}: {str(e)}")
                
        return feeds

    def hunt_threats(self, event_data: Dict) -> List[Dict]:
        """
        Hunt for threats in event data
        
        Args:
            event_data: Security event data
            
        Returns:
            List of identified threats with MITRE ATT&CK mapping
        """
        threats = []
        
        # Apply detection rules
        rule_matches = self._apply_detection_rules(event_data)
        if rule_matches:
            threats.extend(rule_matches)
            
        # Apply hunting patterns
        pattern_matches = self._apply_hunting_patterns(event_data)
        if pattern_matches:
            threats.extend(pattern_matches)
            
        # Check IOC feeds
        ioc_matches = self._check_ioc_feeds(event_data)
        if ioc_matches:
            threats.extend(ioc_matches)
            
        # Enrich threats with MITRE ATT&CK data
        enriched_threats = []
        for threat in threats:
            enriched = self._enrich_with_mitre_data(threat)
            if enriched:
                enriched_threats.append(enriched)
                
        return enriched_threats

    def _apply_detection_rules(self, event_data: Dict) -> List[Dict]:
        """Apply YARA and Sigma rules to event data"""
        matches = []
        
        # Apply YARA rules
        if "file_content" in event_data:
            for rule in self.detection_rules["yara"]:
                try:
                    if self._match_yara_rule(rule, event_data["file_content"]):
                        matches.append({
                            "type": "yara_match",
                            "rule": rule["name"],
                            "confidence": 0.8,
                            "data": event_data
                        })
                except Exception as e:
                    self.logger.error(f"YARA rule matching failed: {str(e)}")
                    
        # Apply Sigma rules
        for rule in self.detection_rules["sigma"]:
            try:
                if self._match_sigma_rule(rule, event_data):
                    matches.append({
                        "type": "sigma_match",
                        "rule": rule["title"],
                        "confidence": 0.7,
                        "data": event_data
                    })
            except Exception as e:
                self.logger.error(f"Sigma rule matching failed: {str(e)}")
                
        # Apply custom rules
        for rule in self.detection_rules["custom"]:
            try:
                if self._match_custom_rule(rule, event_data):
                    matches.append({
                        "type": "custom_match",
                        "rule": rule["name"],
                        "confidence": 0.6,
                        "data": event_data
                    })
            except Exception as e:
                self.logger.error(f"Custom rule matching failed: {str(e)}")
                
        return matches

    def _apply_hunting_patterns(self, event_data: Dict) -> List[Dict]:
        """Apply threat hunting patterns"""
        matches = []
        
        for pattern in self.hunting_patterns:
            try:
                if self._match_hunting_pattern(pattern, event_data):
                    matches.append({
                        "type": "pattern_match",
                        "pattern": pattern["name"],
                        "confidence": pattern["confidence"],
                        "techniques": pattern["mitre_techniques"],
                        "data": event_data
                    })
            except Exception as e:
                self.logger.error(f"Pattern matching failed: {str(e)}")
                
        return matches

    def _check_ioc_feeds(self, event_data: Dict) -> List[Dict]:
        """Check event data against IOC feeds"""
        matches = []
        
        # Extract potential indicators
        indicators = self._extract_indicators(event_data)
        
        # Check each feed
        for feed_name, feed in self.ioc_feeds.items():
            try:
                feed_matches = feed.check_indicators(indicators)
                if feed_matches:
                    matches.extend([
                        {
                            "type": "ioc_match",
                            "feed": feed_name,
                            "ioc": match["indicator"],
                            "confidence": match["confidence"],
                            "data": event_data
                        }
                        for match in feed_matches
                    ])
            except Exception as e:
                self.logger.error(f"IOC feed check failed for {feed_name}: {str(e)}")
                
        return matches

    def _enrich_with_mitre_data(self, threat: Dict) -> Optional[Dict]:
        """Enrich threat with MITRE ATT&CK data"""
        try:
            # Get MITRE techniques
            techniques = []
            if "techniques" in threat:
                for technique_id in threat["techniques"]:
                    if technique_id in self.mitre_techniques:
                        technique = self.mitre_techniques[technique_id]
                        techniques.append({
                            "technique_id": technique.technique_id,
                            "name": technique.name,
                            "tactics": technique.tactics,
                            "description": technique.description,
                            "mitigation": technique.mitigation
                        })
                        
            # Add MITRE data to threat
            enriched = threat.copy()
            enriched["mitre_data"] = {
                "techniques": techniques,
                "tactics": list(set([
                    tactic
                    for technique in techniques
                    for tactic in technique["tactics"]
                ]))
            }
            
            return enriched
            
        except Exception as e:
            self.logger.error(f"MITRE enrichment failed: {str(e)}")
            return None

    def _extract_indicators(self, event_data: Dict) -> Dict[str, Set[str]]:
        """Extract potential indicators from event data"""
        indicators = {
            "ip": set(),
            "domain": set(),
            "url": set(),
            "hash": set(),
            "email": set()
        }
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if isinstance(event_data, dict):
            for value in event_data.values():
                if isinstance(value, str):
                    indicators["ip"].update(re.findall(ip_pattern, value))
                    
        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        if isinstance(event_data, dict):
            for value in event_data.values():
                if isinstance(value, str):
                    indicators["domain"].update(re.findall(domain_pattern, value))
                    
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        if isinstance(event_data, dict):
            for value in event_data.values():
                if isinstance(value, str):
                    indicators["url"].update(re.findall(url_pattern, value))
                    
        # Extract hashes
        hash_patterns = {
            "md5": r'\b[a-fA-F0-9]{32}\b',
            "sha1": r'\b[a-fA-F0-9]{40}\b',
            "sha256": r'\b[a-fA-F0-9]{64}\b'
        }
        if isinstance(event_data, dict):
            for value in event_data.values():
                if isinstance(value, str):
                    for hash_type, pattern in hash_patterns.items():
                        indicators["hash"].update(re.findall(pattern, value))
                        
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if isinstance(event_data, dict):
            for value in event_data.values():
                if isinstance(value, str):
                    indicators["email"].update(re.findall(email_pattern, value))
                    
        return indicators

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add new threat indicator"""
        with self.indicator_lock:
            self.indicators[indicator.value] = indicator

    def get_indicator(self, value: str) -> Optional[ThreatIndicator]:
        """Get threat indicator by value"""
        return self.indicators.get(value)

    def get_mitre_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get MITRE technique by ID"""
        return self.mitre_techniques.get(technique_id)

    def get_mitre_tactic(self, tactic_id: str) -> Optional[str]:
        """Get MITRE tactic name by ID"""
        return self.mitre_tactics.get(tactic_id)
