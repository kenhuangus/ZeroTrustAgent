"""
Security Monitor for Zero Trust Security Agent
"""

from datetime import datetime
from typing import Dict, List, Optional
import threading
from ..utils.logger import get_logger

class SecurityEvent:
    def __init__(self, event_type: str, details: Dict, severity: str = "INFO"):
        self.event_type = event_type
        self.details = details
        self.severity = severity
        self.timestamp = datetime.utcnow()
        self.event_id = f"{self.timestamp.timestamp()}-{event_type}"

class SecurityMonitor:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.events: List[SecurityEvent] = []
        self.alerts: List[SecurityEvent] = []
        self._lock = threading.Lock()
        self.alert_handlers = []

    def record_event(self, event_type: str, details: Dict, severity: str = "INFO") -> None:
        """Record a security event."""
        event = SecurityEvent(event_type, details, severity)
        
        with self._lock:
            self.events.append(event)
            self.logger.info(f"Security event recorded: {event_type} - {details}")
            
            if severity in ["WARNING", "ERROR", "CRITICAL"]:
                self.alerts.append(event)
                self._process_alert(event)

    def get_events(self, 
                  event_type: Optional[str] = None, 
                  severity: Optional[str] = None,
                  start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[SecurityEvent]:
        """Retrieve filtered security events."""
        with self._lock:
            filtered_events = self.events[:]

        if event_type:
            filtered_events = [e for e in filtered_events if e.event_type == event_type]
        if severity:
            filtered_events = [e for e in filtered_events if e.severity == severity]
        if start_time:
            filtered_events = [e for e in filtered_events if e.timestamp >= start_time]
        if end_time:
            filtered_events = [e for e in filtered_events if e.timestamp <= end_time]

        return filtered_events

    def add_alert_handler(self, handler_func):
        """Add a callback function to handle alerts."""
        self.alert_handlers.append(handler_func)

    def _process_alert(self, event: SecurityEvent) -> None:
        """Process security alerts."""
        for handler in self.alert_handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Error in alert handler: {str(e)}")

    def get_alerts(self, severity: Optional[str] = None) -> List[SecurityEvent]:
        """Retrieve security alerts."""
        with self._lock:
            if severity:
                return [a for a in self.alerts if a.severity == severity]
            return self.alerts[:]

    def clear_events(self, older_than: Optional[datetime] = None) -> int:
        """Clear events from memory."""
        with self._lock:
            if older_than:
                initial_count = len(self.events)
                self.events = [e for e in self.events if e.timestamp > older_than]
                return initial_count - len(self.events)
            else:
                count = len(self.events)
                self.events = []
                return count
