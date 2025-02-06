"""
Configuration utility for Zero Trust Security Agent
"""

import yaml
from typing import Dict, Any
import os

def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            
        return _validate_config(config)
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing configuration file: {str(e)}")
    except Exception as e:
        raise Exception(f"Error loading configuration: {str(e)}")

def _validate_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Validate configuration structure and set defaults."""
    required_sections = ["auth", "policies", "logging"]
    
    for section in required_sections:
        if section not in config:
            config[section] = {}
    
    # Set default authentication configuration
    if "auth" in config:
        config["auth"].setdefault("token_expiry", 3600)
        
    # Set default logging configuration
    if "logging" in config:
        config["logging"].setdefault("level", "INFO")
        
    # Validate policies
    if "policies" in config:
        policies = config["policies"].get("policies", [])
        for policy in policies:
            if not all(k in policy for k in ["name", "conditions", "effect"]):
                raise ValueError(f"Invalid policy configuration: {policy}")
            if policy["effect"].lower() not in ["allow", "deny"]:
                raise ValueError(f"Invalid policy effect: {policy['effect']}")
    
    return config
