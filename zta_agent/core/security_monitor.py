"""
Security Monitoring System for Zero Trust Agent
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import ipaddress
import geoip2.database
import requests
from dataclasses import dataclass
import json
import logging
from threading import Lock
import schedule
import threading
from .security_logger import SecurityLogger
from .security_analysis.llm_analyzer import LLMAnalyzer, AnalysisResult

@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: float
    event_type: str
    severity: str
    source_ip: Optional[str]
    user_agent: Optional[str]
    identity: Optional[str]
    details: Dict
    location_info: Optional[Dict] = None
    threat_intel: Optional[Dict] = None

class RateLimiter:
    """Rate limiting implementation using sliding window"""
    
    def __init__(self, window_size: int, max_requests: int):
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests = defaultdict(list)
        self.lock = Lock()

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed based on rate limits"""
        with self.lock:
            now = time.time()
            self.requests[key] = [t for t in self.requests[key] if t > now - self.window_size]
            
            if len(self.requests[key]) >= self.max_requests:
                return False
                
            self.requests[key].append(now)
            return True

class SecurityMonitor:
    """Advanced security monitoring system"""

    def __init__(self, config: Dict):
        """
        Initialize security monitor
        
        Args:
            config: Configuration dictionary containing:
                - geoip_db_path: Path to GeoIP database
                - threat_intel_api_key: API key for threat intelligence
                - alert_thresholds: Dictionary of event types and their alert thresholds
                - ip_blacklist: List of blocked IP addresses/ranges
                - ip_whitelist: List of trusted IP addresses/ranges
                - rate_limits: Dictionary of rate limit configurations
                - llm: LLM configuration for security analysis
        """
        self.config = config
        self.logger = SecurityLogger(config)
        
        # Initialize LLM analyzer if configured
        self.llm_analyzer = None
        if "llm" in config:
            self.llm_analyzer = LLMAnalyzer(config["llm"])
        
        # Initialize GeoIP database
        self.geoip_reader = geoip2.database.Reader(config["geoip_db_path"])
        
        # Initialize rate limiters
        self.rate_limiters = {
            "auth": RateLimiter(
                config["rate_limits"]["auth"]["window"],
                config["rate_limits"]["auth"]["max_requests"]
            ),
            "api": RateLimiter(
                config["rate_limits"]["api"]["window"],
                config["rate_limits"]["api"]["max_requests"]
            )
        }
        
        # Initialize counters and caches
        self.event_counters = defaultdict(lambda: defaultdict(int))
        self.suspicious_ips = set()
        self.blocked_ips = self._load_ip_lists(config["ip_blacklist"])
        self.trusted_ips = self._load_ip_lists(config["ip_whitelist"])
        self.auth_failures = defaultdict(list)
        self.session_cache = {}
        
        # Alert thresholds
        self.alert_thresholds = config["alert_thresholds"]
        
        # Start background tasks
        self._start_background_tasks()

    def _load_ip_lists(self, ip_list: List[str]) -> Set[ipaddress.IPv4Network]:
        """Load and parse IP address lists"""
        networks = set()
        for ip_entry in ip_list:
            try:
                if "/" in ip_entry:
                    networks.add(ipaddress.IPv4Network(ip_entry))
                else:
                    networks.add(ipaddress.IPv4Network(f"{ip_entry}/32"))
            except ValueError:
                self.logger.error(f"Invalid IP address or network: {ip_entry}")
        return networks

    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is in the blocked list"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return any(ip_obj in network for network in self.blocked_ips)
        except ValueError:
            return False

    def _is_ip_trusted(self, ip: str) -> bool:
        """Check if an IP is in the trusted list"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return any(ip_obj in network for network in self.trusted_ips)
        except ValueError:
            return False

    def _get_location_info(self, ip: str) -> Optional[Dict]:
        """Get location information for an IP address"""
        try:
            response = self.geoip_reader.city(ip)
            return {
                "country": response.country.name,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone
            }
        except Exception:
            return None

    def _get_threat_intel(self, ip: str) -> Optional[Dict]:
        """Query threat intelligence data for an IP"""
        try:
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self.config["threat_intel_api_key"]},
                params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "abuse_score": data["data"]["abuseConfidenceScore"],
                    "reports": data["data"]["totalReports"],
                    "last_reported": data["data"].get("lastReportedAt")
                }
        except Exception:
            pass
        return None

    def record_event(self, event_type: str, details: Dict, severity: str = "info") -> None:
        """
        Record a security event
        
        Args:
            event_type: Type of security event
            details: Event details dictionary
            severity: Event severity (info, warning, error, critical)
        """
        # Extract common fields
        source_ip = details.get("ip_address")
        user_agent = details.get("user_agent")
        identity = details.get("identity")
        
        # Skip processing for trusted IPs
        if source_ip and self._is_ip_trusted(source_ip):
            return

        # Check for blocked IPs
        if source_ip and self._is_ip_blocked(source_ip):
            self.logger.warning(f"Blocked IP attempt: {source_ip}")
            return

        # Get additional context
        location_info = None
        threat_intel = None
        if source_ip:
            location_info = self._get_location_info(source_ip)
            threat_intel = self._get_threat_intel(source_ip)

        # Create security event
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            user_agent=user_agent,
            identity=identity,
            details=details,
            location_info=location_info,
            threat_intel=threat_intel
        )

        # Update counters
        self.event_counters[event_type]["total"] += 1
        if severity in ["warning", "error", "critical"]:
            self.event_counters[event_type][severity] += 1

        # Check for suspicious activity
        self._analyze_event(event)

        # Log the event
        self._log_event(event)

        # Check alert thresholds
        self._check_alert_thresholds(event_type)

    def _analyze_event(self, event: SecurityEvent) -> None:
        """Analyze event for suspicious patterns"""
        if event.source_ip:
            # Check for authentication failures
            if event.event_type == "authentication_failure":
                self.auth_failures[event.source_ip].append(event.timestamp)
                recent_failures = [t for t in self.auth_failures[event.source_ip]
                                 if t > time.time() - 3600]
                self.auth_failures[event.source_ip] = recent_failures

                if len(recent_failures) >= self.config["max_auth_failures"]:
                    self.suspicious_ips.add(event.source_ip)
                    self._trigger_alert("excessive_auth_failures", {
                        "ip": event.source_ip,
                        "count": len(recent_failures),
                        "window": "1 hour"
                    })

            # Check threat intelligence score
            if event.threat_intel and event.threat_intel["abuse_score"] > 50:
                self.suspicious_ips.add(event.source_ip)
                self._trigger_alert("high_threat_score", {
                    "ip": event.source_ip,
                    "score": event.threat_intel["abuse_score"]
                })

        # Perform LLM analysis for suspicious events
        if (event.severity in ["warning", "error", "critical"] and 
            self.llm_analyzer is not None):
            self._perform_llm_analysis(event)

    def _perform_llm_analysis(self, event: SecurityEvent) -> None:
        """Perform LLM-based analysis of suspicious events"""
        try:
            # Prepare event data for analysis
            event_data = {
                "timestamp": datetime.fromtimestamp(event.timestamp).isoformat(),
                "event_type": event.event_type,
                "severity": event.severity,
                "source_ip": event.source_ip,
                "user_agent": event.user_agent,
                "identity": event.identity,
                "details": event.details,
                "location_info": event.location_info,
                "threat_intel": event.threat_intel
            }

            # Get LLM analysis
            analysis_result = self.llm_analyzer.analyze_event(event_data)
            
            if analysis_result:
                # Log the analysis
                self.logger.info(
                    "LLM Analysis Result",
                    extra={
                        "event_id": event.timestamp,
                        "threat_level": analysis_result.threat_level,
                        "confidence": analysis_result.confidence,
                        "analysis": analysis_result.analysis,
                        "recommendations": analysis_result.recommendations,
                        "patterns": analysis_result.patterns_identified,
                        "false_positive_prob": analysis_result.false_positive_probability
                    }
                )

                # Take automated actions based on analysis
                if (analysis_result.threat_level in ["high", "critical"] and 
                    analysis_result.confidence > 0.8 and
                    analysis_result.false_positive_probability < 0.2):
                    
                    self._trigger_alert("llm_analysis_threat", {
                        "event_data": event_data,
                        "analysis": analysis_result,
                        "automated_response": True
                    })

                    # Apply recommended actions
                    self._apply_llm_recommendations(
                        event.source_ip,
                        event.identity,
                        analysis_result.recommendations
                    )

        except Exception as e:
            self.logger.error(f"LLM analysis failed: {str(e)}")

    def _apply_llm_recommendations(
        self,
        source_ip: Optional[str],
        identity: Optional[str],
        recommendations: List[str]
    ) -> None:
        """Apply recommendations from LLM analysis"""
        for recommendation in recommendations:
            recommendation = recommendation.lower()
            
            if "block ip" in recommendation and source_ip:
                self.add_to_blacklist(source_ip)
                self.logger.info(f"Blocked IP {source_ip} based on LLM recommendation")
                
            elif "revoke tokens" in recommendation and identity:
                # Assuming token_store is accessible
                if hasattr(self, 'token_store'):
                    self.token_store.revoke_all_user_tokens(identity)
                    self.logger.info(
                        f"Revoked all tokens for {identity} based on LLM recommendation"
                    )
                    
            elif "increase monitoring" in recommendation and source_ip:
                # Add to enhanced monitoring list
                self.suspicious_ips.add(source_ip)
                self.logger.info(
                    f"Added {source_ip} to enhanced monitoring based on LLM recommendation"
                )
                
            elif "notify admin" in recommendation:
                self._trigger_alert("llm_recommendation", {
                    "recommendation": recommendation,
                    "source_ip": source_ip,
                    "identity": identity
                })

    def _check_alert_thresholds(self, event_type: str) -> None:
        """Check if alert thresholds have been exceeded"""
        if event_type in self.alert_thresholds:
            threshold = self.alert_thresholds[event_type]
            count = self.event_counters[event_type]["total"]
            
            if count >= threshold:
                self._trigger_alert("threshold_exceeded", {
                    "event_type": event_type,
                    "count": count,
                    "threshold": threshold
                })

    def _trigger_alert(self, alert_type: str, details: Dict) -> None:
        """Trigger a security alert"""
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "type": alert_type,
            "details": details
        }
        
        # Log alert
        self.logger.error(f"Security Alert: {json.dumps(alert)}")
        
        # TODO: Implement alert notifications (email, Slack, etc.)

    def _log_event(self, event: SecurityEvent) -> None:
        """Log security event with appropriate severity"""
        log_message = {
            "timestamp": datetime.fromtimestamp(event.timestamp).isoformat(),
            "event_type": event.event_type,
            "severity": event.severity,
            "source_ip": event.source_ip,
            "identity": event.identity,
            "details": event.details
        }
        
        if event.location_info:
            log_message["location"] = event.location_info
        if event.threat_intel:
            log_message["threat_intel"] = event.threat_intel

        if event.severity == "critical":
            self.logger.critical(json.dumps(log_message))
        elif event.severity == "error":
            self.logger.error(json.dumps(log_message))
        elif event.severity == "warning":
            self.logger.warning(json.dumps(log_message))
        else:
            self.logger.info(json.dumps(log_message))

    def check_rate_limit(self, key: str, limit_type: str = "api") -> bool:
        """Check if a request is within rate limits"""
        return self.rate_limiters[limit_type].is_allowed(key)

    def is_suspicious(self, ip: str) -> bool:
        """Check if an IP is marked as suspicious"""
        return ip in self.suspicious_ips

    def _cleanup_old_data(self) -> None:
        """Clean up old data from caches and counters"""
        now = time.time()
        
        # Clean up auth failures older than 24 hours
        for ip in list(self.auth_failures.keys()):
            self.auth_failures[ip] = [t for t in self.auth_failures[ip]
                                    if t > now - 86400]
            if not self.auth_failures[ip]:
                del self.auth_failures[ip]

        # Clean up suspicious IPs after 24 hours
        self.suspicious_ips = {ip for ip in self.suspicious_ips
                             if self.auth_failures.get(ip, [])}

        # Reset daily counters
        if datetime.now().hour == 0:
            self.event_counters.clear()

    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks"""
        schedule.every(1).hours.do(self._cleanup_old_data)
        
        def run_scheduled_tasks():
            while True:
                schedule.run_pending()
                time.sleep(60)

        cleanup_thread = threading.Thread(target=run_scheduled_tasks, daemon=True)
        cleanup_thread.start()

    def get_security_metrics(self) -> Dict:
        """Get current security metrics"""
        return {
            "event_counts": dict(self.event_counters),
            "suspicious_ips": len(self.suspicious_ips),
            "blocked_ips": len(self.blocked_ips),
            "auth_failures": {
                ip: len(failures) for ip, failures in self.auth_failures.items()
            }
        }

    def add_to_blacklist(self, ip: str) -> bool:
        """Add an IP to the blacklist"""
        try:
            network = ipaddress.IPv4Network(ip if "/" in ip else f"{ip}/32")
            self.blocked_ips.add(network)
            return True
        except ValueError:
            return False

    def remove_from_blacklist(self, ip: str) -> bool:
        """Remove an IP from the blacklist"""
        try:
            network = ipaddress.IPv4Network(ip if "/" in ip else f"{ip}/32")
            if network in self.blocked_ips:
                self.blocked_ips.remove(network)
                return True
        except ValueError:
            pass
        return False

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, 'geoip_reader'):
            self.geoip_reader.close()
