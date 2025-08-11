"""
LLM-based Security Log Analysis
"""

from typing import Dict, List, Optional, Union
import json
import openai
import anthropic
import google.cloud.aiplatform as vertexai
from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging

@dataclass
class AnalysisResult:
    """Result of LLM security analysis"""
    threat_level: str  # low, medium, high, critical
    confidence: float  # 0.0 to 1.0
    analysis: str  # Detailed analysis
    recommendations: List[str]  # List of recommended actions
    patterns_identified: List[str]  # List of identified attack patterns
    false_positive_probability: float  # 0.0 to 1.0

class LLMProvider(ABC):
    """Base class for LLM providers"""
    
    @abstractmethod
    def analyze_security_event(self, event_data: Dict) -> AnalysisResult:
        """Analyze a security event using the LLM"""
        pass

    def _create_prompt(self, event_data: Dict) -> str:
        """Create a standardized prompt for security analysis"""
        return f"""As a security expert, analyze this security event and provide:
1. Threat level assessment
2. Detailed analysis of the activity
3. Identification of any attack patterns
4. Recommendations for response
5. False positive probability assessment

Security Event Data:
{json.dumps(event_data, indent=2)}

Focus on:
- Unusual patterns or behaviors
- Known attack signatures
- Correlation with threat intelligence
- Geographic anomalies
- Authentication patterns
- Resource access patterns

Provide your analysis in a structured format."""

class OpenAIProvider(LLMProvider):
    """OpenAI-based security analysis"""
    
    def __init__(self, config: Dict):
        """Initialize OpenAI provider"""
        openai.api_key = config["api_key"]
        self.model = config.get("model", "gpt-4")
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = config.get("max_tokens", 1000)

    def analyze_security_event(self, event_data: Dict) -> AnalysisResult:
        """Analyze security event using OpenAI"""
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert security analyst specializing in threat detection and incident response."},
                    {"role": "user", "content": self._create_prompt(event_data)}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            
            # Parse the response
            analysis = response.choices[0].message.content
            return self._parse_analysis(analysis)
        except Exception as e:
            logging.error(f"OpenAI analysis failed: {str(e)}")
            raise

class AnthropicProvider(LLMProvider):
    """Anthropic Claude-based security analysis"""
    
    def __init__(self, config: Dict):
        """Initialize Anthropic provider"""
        self.client = anthropic.Client(api_key=config["api_key"])
        self.model = config.get("model", "claude-2")
        self.max_tokens = config.get("max_tokens", 1000)

    def analyze_security_event(self, event_data: Dict) -> AnalysisResult:
        """Analyze security event using Anthropic Claude"""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{
                    "role": "user",
                    "content": self._create_prompt(event_data)
                }]
            )
            
            return self._parse_analysis(response.content)
        except Exception as e:
            logging.error(f"Anthropic analysis failed: {str(e)}")
            raise

class VertexAIProvider(LLMProvider):
    """Google Vertex AI-based security analysis"""
    
    def __init__(self, config: Dict):
        """Initialize Vertex AI provider"""
        vertexai.init(
            project=config["project_id"],
            location=config["location"]
        )
        self.model = config.get("model", "text-bison@002")
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = config.get("max_tokens", 1000)

    def analyze_security_event(self, event_data: Dict) -> AnalysisResult:
        """Analyze security event using Vertex AI"""
        try:
            model = vertexai.TextGenerationModel.from_pretrained(self.model)
            response = model.predict(
                self._create_prompt(event_data),
                temperature=self.temperature,
                max_output_tokens=self.max_tokens
            )
            
            return self._parse_analysis(response.text)
        except Exception as e:
            logging.error(f"Vertex AI analysis failed: {str(e)}")
            raise

class LLMAnalyzer:
    """Main class for LLM-based security analysis"""
    
    def __init__(self, config: Dict):
        """
        Initialize LLM analyzer with configuration
        
        Config should include:
        - provider: LLM provider (openai, anthropic, vertex)
        - api_key: API key for the provider
        - model: Model name
        - backup_providers: List of backup providers
        """
        self.config = config
        self.providers: Dict[str, LLMProvider] = {}
        
        # Initialize primary provider
        provider_type = config["provider"]
        self.providers[provider_type] = self._create_provider(provider_type, config)
        
        # Initialize backup providers
        for backup in config.get("backup_providers", []):
            if backup != provider_type:
                self.providers[backup] = self._create_provider(backup, config)

    def _create_provider(self, provider_type: str, config: Dict) -> LLMProvider:
        """Create a provider instance based on type"""
        if provider_type == "openai":
            return OpenAIProvider(config)
        elif provider_type == "anthropic":
            return AnthropicProvider(config)
        elif provider_type == "vertex":
            return VertexAIProvider(config)
        else:
            raise ValueError(f"Unsupported provider type: {provider_type}")

    def analyze_event(self, event_data: Dict) -> Optional[AnalysisResult]:
        """
        Analyze a security event using configured LLM providers
        
        Args:
            event_data: Security event data to analyze
            
        Returns:
            AnalysisResult if successful, None if all providers fail
        """
        errors = []
        
        # Try primary provider first
        primary_provider = self.config["provider"]
        try:
            return self.providers[primary_provider].analyze_security_event(event_data)
        except Exception as e:
            errors.append(f"{primary_provider} failed: {str(e)}")
        
        # Try backup providers
        for backup in self.config.get("backup_providers", []):
            try:
                return self.providers[backup].analyze_security_event(event_data)
            except Exception as e:
                errors.append(f"{backup} failed: {str(e)}")
        
        # All providers failed
        logging.error(f"All LLM providers failed: {'; '.join(errors)}")
        return None

    def _parse_analysis(self, analysis_text: str) -> AnalysisResult:
        """Parse LLM response into structured analysis result"""
        # Extract information using basic parsing
        # This could be improved with better parsing logic
        lines = analysis_text.split("\n")
        threat_level = "medium"  # default
        confidence = 0.5  # default
        recommendations = []
        patterns = []
        false_positive_prob = 0.5  # default
        
        for line in lines:
            line = line.strip().lower()
            if "threat level:" in line:
                threat_level = line.split(":")[1].strip()
            elif "confidence:" in line:
                try:
                    confidence = float(line.split(":")[1].strip())
                except ValueError:
                    pass
            elif "recommendation:" in line:
                recommendations.append(line.split(":")[1].strip())
            elif "pattern identified:" in line:
                patterns.append(line.split(":")[1].strip())
            elif "false positive probability:" in line:
                try:
                    false_positive_prob = float(line.split(":")[1].strip())
                except ValueError:
                    pass
        
        return AnalysisResult(
            threat_level=threat_level,
            confidence=confidence,
            analysis=analysis_text,
            recommendations=recommendations,
            patterns_identified=patterns,
            false_positive_probability=false_positive_prob
        )
