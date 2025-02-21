import unittest
from unittest.mock import Mock, patch
import numpy as np
from datetime import datetime, timedelta
import json

from zta_agent.core.security_analysis.behavioral_analytics import BehavioralAnalytics
from zta_agent.core.security_analysis.threat_hunter import ThreatHunter
from zta_agent.core.security_monitor import SecurityMonitor

class TestBehavioralAnalytics(unittest.TestCase):
    def setUp(self):
        self.config = {
            'behavioral_analytics': {
                'model_path': 'models/',
                'training_interval': 86400,
                'risk_weights': {
                    'anomaly': 0.4,
                    'sequence': 0.3,
                    'profile': 0.3
                }
            }
        }
        self.analytics = BehavioralAnalytics(self.config)

    @patch('joblib.load')
    def test_analyze_user_behavior(self, mock_load):
        # Mock the isolation forest model
        mock_model = Mock()
        mock_model.predict.return_value = np.array([-1])  # Anomaly
        mock_model.decision_function.return_value = np.array([-0.5])  # Anomaly score
        mock_load.return_value = mock_model

        event_data = {
            'timestamp': datetime.now().isoformat(),
            'action': 'resource_access',
            'resource': '/api/sensitive_data',
            'ip_address': '192.168.1.100',
            'user_agent': 'Mozilla/5.0',
            'location': 'US-NYC'
        }

        risk_score, anomalies = self.analytics.analyze_user_behavior('user123', event_data)
        
        self.assertIsInstance(risk_score, float)
        self.assertGreaterEqual(risk_score, 0)
        self.assertLessEqual(risk_score, 1)
        self.assertIsInstance(anomalies, list)

    def test_profile_update(self):
        user_id = 'test_user'
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'action': 'login',
            'location': 'US-NYC',
            'device': 'Windows-Chrome'
        }

        # Update profile
        self.analytics.update_user_profile(user_id, event_data)
        
        # Get profile
        profile = self.analytics.get_user_profile(user_id)
        
        self.assertIsNotNone(profile)
        self.assertIn('locations', profile)
        self.assertIn('devices', profile)
        self.assertIn('US-NYC', profile['locations'])
        self.assertIn('Windows-Chrome', profile['devices'])

class TestThreatHunter(unittest.TestCase):
    def setUp(self):
        self.config = {
            'threat_hunting': {
                'mitre': {
                    'cache_file': 'cache/mitre_attack.json',
                    'minimum_confidence': 0.7
                },
                'rules': {
                    'yara_rules_path': 'rules/yara/',
                    'sigma_rules_path': 'rules/sigma/'
                }
            }
        }
        self.hunter = ThreatHunter(self.config)

    def test_hunt_threats(self):
        event_data = {
            'source_ip': '192.168.1.100',
            'destination_ip': '203.0.113.1',
            'protocol': 'HTTPS',
            'payload_size': 1500,
            'timestamp': datetime.now().isoformat()
        }

        threats = self.hunter.hunt_threats(event_data)
        
        self.assertIsInstance(threats, list)
        for threat in threats:
            self.assertIn('type', threat)
            self.assertIn('confidence', threat)
            self.assertIn('details', threat)

    @patch('requests.get')
    def test_ioc_check(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'indicators': [
                {
                    'type': 'ip',
                    'value': '203.0.113.1',
                    'confidence': 0.8
                }
            ]
        }
        mock_get.return_value = mock_response

        ioc_matches = self.hunter.check_ioc('203.0.113.1', 'ip')
        
        self.assertIsInstance(ioc_matches, list)
        self.assertGreater(len(ioc_matches), 0)
        for match in ioc_matches:
            self.assertIn('type', match)
            self.assertIn('confidence', match)

class TestSecurityMonitor(unittest.TestCase):
    def setUp(self):
        self.config = {
            'monitoring': {
                'log_path': 'logs/',
                'alert_threshold': 0.7
            }
        }
        self.monitor = SecurityMonitor(self.config)

    def test_record_event(self):
        event = {
            'event_type': 'authentication_attempt',
            'details': {
                'user_id': 'user123',
                'ip_address': '192.168.1.100',
                'location': 'US-NYC',
                'device': 'Windows-Chrome'
            },
            'severity': 'info'
        }

        event_id = self.monitor.record_event(**event)
        self.assertIsNotNone(event_id)

        # Verify event was recorded
        events = self.monitor.get_events(
            start_time=datetime.now() - timedelta(minutes=1),
            end_time=datetime.now() + timedelta(minutes=1)
        )
        
        self.assertGreater(len(events), 0)
        found_event = False
        for e in events:
            if e['id'] == event_id:
                found_event = True
                self.assertEqual(e['event_type'], event['event_type'])
                self.assertEqual(e['details'], event['details'])
                self.assertEqual(e['severity'], event['severity'])
        self.assertTrue(found_event)

    def test_get_alerts(self):
        # Record a high-severity event
        event = {
            'event_type': 'suspicious_activity',
            'details': {
                'user_id': 'user123',
                'activity': 'multiple_failed_logins',
                'count': 5
            },
            'severity': 'high'
        }
        self.monitor.record_event(**event)

        # Get alerts
        alerts = self.monitor.get_alerts(severity='high')
        
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)
        for alert in alerts:
            self.assertEqual(alert['severity'], 'high')
            self.assertIn('timestamp', alert)
            self.assertIn('event_type', alert)
            self.assertIn('details', alert)

if __name__ == '__main__':
    unittest.main()
