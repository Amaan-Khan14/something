"""
Hybrid Attack Detection Engine
Combines pattern matching, ML classification, and heuristic analysis
"""
import re
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import pickle
import os

from app.utils.attack_patterns import AttackPatterns

logger = logging.getLogger(__name__)


class DetectionResult:
    """Result from attack detection"""

    def __init__(
        self,
        is_attack: bool,
        attack_type: Optional[str] = None,
        attack_subtype: Optional[str] = None,
        confidence_score: float = 0.0,
        severity: str = "Low",
        detection_method: str = "unknown",
        matched_patterns: Optional[List[str]] = None,
    ):
        self.is_attack = is_attack
        self.attack_type = attack_type
        self.attack_subtype = attack_subtype
        self.confidence_score = confidence_score
        self.severity = severity
        self.detection_method = detection_method
        self.matched_patterns = matched_patterns or []

    def to_dict(self) -> Dict:
        return {
            "is_attack": self.is_attack,
            "attack_type": self.attack_type,
            "attack_subtype": self.attack_subtype,
            "confidence_score": self.confidence_score,
            "severity": self.severity,
            "detection_method": self.detection_method,
            "matched_patterns": self.matched_patterns,
        }


class DetectionEngine:
    """Hybrid detection engine using pattern matching and ML"""

    def __init__(self, ml_model_path: Optional[str] = None):
        """
        Initialize detection engine.

        Args:
            ml_model_path: Path to trained ML model (optional)
        """
        # Compile regex patterns
        self.patterns = AttackPatterns.compile_patterns()
        logger.info(f"Loaded {sum(len(p) for p in self.patterns.values())} detection patterns")

        # Load ML model if available
        self.ml_model = None
        self.vectorizer = None
        self.label_encoder = None

        if ml_model_path and os.path.exists(ml_model_path):
            try:
                self._load_ml_model(ml_model_path)
                logger.info("ML model loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load ML model: {e}")

    def _load_ml_model(self, model_path: str):
        """Load trained ML model and preprocessing components"""
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        self.ml_model = model_data.get('model')
        self.vectorizer = model_data.get('vectorizer')
        self.label_encoder = model_data.get('label_encoder')

    def detect(self, url: str, method: str = "GET", user_agent: Optional[str] = None) -> DetectionResult:
        """
        Detect attacks in URL using hybrid approach.

        Args:
            url: URL to analyze
            method: HTTP method
            user_agent: User agent string

        Returns:
            DetectionResult object
        """
        # Try pattern matching first (fast path)
        pattern_result = self._pattern_based_detection(url)

        # If high-confidence pattern match, return immediately
        if pattern_result.is_attack and pattern_result.confidence_score >= 0.90:
            return pattern_result

        # Try ML detection if model is available
        if self.ml_model:
            ml_result = self._ml_based_detection(url)

            # Combine results
            if ml_result.is_attack or pattern_result.is_attack:
                return self._combine_results(pattern_result, ml_result)

        # Heuristic analysis for low-confidence cases
        if pattern_result.confidence_score < 0.70:
            heuristic_result = self._heuristic_analysis(url)
            if heuristic_result.is_attack:
                return heuristic_result

        # Return pattern result if available, otherwise benign
        if pattern_result.is_attack:
            return pattern_result

        return DetectionResult(is_attack=False, detection_method="hybrid")

    def _pattern_based_detection(self, url: str) -> DetectionResult:
        """
        Pattern-based detection using regex signatures.

        Args:
            url: URL to analyze

        Returns:
            DetectionResult
        """
        # Decode URL for better matching
        decoded_url = unquote(url).lower()

        best_match = None
        best_confidence = 0.0

        # Check each pattern category
        for attack_type, pattern_list in self.patterns.items():
            for pattern, subtype, severity, base_confidence in pattern_list:
                if pattern.search(decoded_url):
                    # Found a match
                    match_confidence = base_confidence * 100  # Convert to 0-100 scale

                    if match_confidence > best_confidence:
                        best_confidence = match_confidence
                        best_match = (attack_type, subtype, severity, pattern.pattern)

        if best_match:
            attack_type, subtype, severity, pattern_str = best_match
            return DetectionResult(
                is_attack=True,
                attack_type=attack_type,
                attack_subtype=subtype,
                confidence_score=best_confidence,
                severity=severity,
                detection_method="pattern",
                matched_patterns=[pattern_str],
            )

        return DetectionResult(is_attack=False, detection_method="pattern")

    def _ml_based_detection(self, url: str) -> DetectionResult:
        """
        ML-based detection using trained classifier.

        Args:
            url: URL to analyze

        Returns:
            DetectionResult
        """
        if not self.ml_model or not self.vectorizer:
            return DetectionResult(is_attack=False, detection_method="ml")

        try:
            # Extract features
            features = self._extract_features(url)

            # Vectorize
            X = self.vectorizer.transform([features])

            # Predict
            prediction = self.ml_model.predict(X)[0]
            probabilities = self.ml_model.predict_proba(X)[0]

            # Get confidence
            confidence = max(probabilities) * 100

            # Decode label
            if self.label_encoder:
                attack_type = self.label_encoder.inverse_transform([prediction])[0]
            else:
                attack_type = str(prediction)

            # Classify as attack if not benign and confidence is high
            is_attack = attack_type != "benign" and confidence >= 60.0

            if is_attack:
                return DetectionResult(
                    is_attack=True,
                    attack_type=attack_type,
                    confidence_score=confidence,
                    severity=self._estimate_severity(attack_type),
                    detection_method="ml",
                )

            return DetectionResult(is_attack=False, detection_method="ml")

        except Exception as e:
            logger.error(f"ML detection error: {e}")
            return DetectionResult(is_attack=False, detection_method="ml")

    def _heuristic_analysis(self, url: str) -> DetectionResult:
        """
        Heuristic-based analysis for anomaly detection.

        Args:
            url: URL to analyze

        Returns:
            DetectionResult
        """
        suspicious_score = 0
        indicators = []

        decoded_url = unquote(url).lower()

        # Check for suspicious characteristics
        # 1. Excessive length
        if len(decoded_url) > 500:
            suspicious_score += 20
            indicators.append("excessive_length")

        # 2. Excessive special characters
        special_chars = sum(1 for c in decoded_url if not c.isalnum() and c not in ['/', '?', '&', '=', '.', '-'])
        if special_chars > 50:
            suspicious_score += 15
            indicators.append("excessive_special_chars")

        # 3. Encoding obfuscation
        if decoded_url.count('%') > 10:
            suspicious_score += 10
            indicators.append("excessive_encoding")

        # 4. Multiple slashes or dots
        if '...' in decoded_url or '///' in decoded_url:
            suspicious_score += 15
            indicators.append("path_anomaly")

        # 5. Suspicious keywords
        suspicious_keywords = ['eval', 'exec', 'system', 'base64', 'cmd', 'shell', 'passwd', 'shadow']
        for keyword in suspicious_keywords:
            if keyword in decoded_url:
                suspicious_score += 10
                indicators.append(f"keyword_{keyword}")

        # 6. SQL keywords
        sql_keywords = ['select', 'union', 'insert', 'delete', 'drop', 'update', 'where']
        sql_count = sum(1 for kw in sql_keywords if kw in decoded_url)
        if sql_count >= 2:
            suspicious_score += 15
            indicators.append("sql_keywords")

        # Determine if suspicious
        if suspicious_score >= 40:
            return DetectionResult(
                is_attack=True,
                attack_type="Anomalous Request",
                confidence_score=min(suspicious_score, 100),
                severity="Medium" if suspicious_score < 60 else "High",
                detection_method="heuristic",
                matched_patterns=indicators,
            )

        return DetectionResult(is_attack=False, detection_method="heuristic")

    def _combine_results(self, pattern_result: DetectionResult, ml_result: DetectionResult) -> DetectionResult:
        """
        Combine pattern and ML results for final decision.

        Args:
            pattern_result: Result from pattern matching
            ml_result: Result from ML classification

        Returns:
            Combined DetectionResult
        """
        # If both agree it's an attack, use higher confidence
        if pattern_result.is_attack and ml_result.is_attack:
            if pattern_result.confidence_score >= ml_result.confidence_score:
                pattern_result.detection_method = "hybrid"
                pattern_result.confidence_score = min(
                    (pattern_result.confidence_score + ml_result.confidence_score) / 2 + 10,
                    100
                )
                return pattern_result
            else:
                ml_result.detection_method = "hybrid"
                ml_result.confidence_score = min(
                    (pattern_result.confidence_score + ml_result.confidence_score) / 2 + 10,
                    100
                )
                return ml_result

        # If only one says attack, return that one if confidence is decent
        if pattern_result.is_attack and pattern_result.confidence_score >= 70:
            return pattern_result

        if ml_result.is_attack and ml_result.confidence_score >= 70:
            return ml_result

        # Default to not attack
        return DetectionResult(is_attack=False, detection_method="hybrid")

    def _extract_features(self, url: str) -> str:
        """
        Extract features from URL for ML model.
        For now, returns the URL itself (will be vectorized).

        Args:
            url: URL to extract features from

        Returns:
            Feature string
        """
        # Decode and normalize
        decoded_url = unquote(url).lower()
        return decoded_url

    def _estimate_severity(self, attack_type: str) -> str:
        """
        Estimate severity based on attack type.

        Args:
            attack_type: Type of attack

        Returns:
            Severity level
        """
        critical_attacks = ["SQL Injection", "Command Injection", "XXE", "Web Shell"]
        high_attacks = ["XSS", "Directory Traversal", "SSRF", "RFI", "LFI"]
        medium_attacks = ["Open Redirect", "LDAP Injection", "Template Injection"]

        for attack in critical_attacks:
            if attack.lower() in attack_type.lower():
                return "Critical"

        for attack in high_attacks:
            if attack.lower() in attack_type.lower():
                return "High"

        for attack in medium_attacks:
            if attack.lower() in attack_type.lower():
                return "Medium"

        return "Low"

    def batch_detect(self, urls: List[str]) -> List[DetectionResult]:
        """
        Detect attacks in multiple URLs efficiently.

        Args:
            urls: List of URLs to analyze

        Returns:
            List of DetectionResult objects
        """
        results = []
        for url in urls:
            result = self.detect(url)
            results.append(result)

        return results
