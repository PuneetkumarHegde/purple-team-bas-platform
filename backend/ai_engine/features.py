"""
Feature Extraction for AI Threat Detection
Extracts Shannon entropy, special character ratios, path depths, and encoding anomalies.
"""

from __future__ import annotations

import math
from collections import Counter
from urllib.parse import unquote, urlparse

from .patterns import DOUBLE_ENCODED, ENCODED_CHARS


def shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string (measures unpredictability/randomness).
    High entropy in parameters often indicates obfuscated payloads or token tampering.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(uri: str, payload: str = "") -> dict[str, float | int | bool]:
    """
    Extracts numerical and structural features from a target URI and payload.
    """
    parsed = urlparse(uri)
    path = parsed.path
    query = parsed.query
    full_string = f"{path}?{query}" if query else path
    if payload:
        full_string += f"&payload={payload}"

    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)
    path_entropy = shannon_entropy(path)
    query_entropy = shannon_entropy(query)
    combined_entropy = shannon_entropy(full_string)

    special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
    special_count = sum(1 for c in full_string if c in special_chars)
    special_char_ratio = special_count / len(full_string) if full_string else 0.0

    has_encoded = bool(ENCODED_CHARS.search(full_string))
    has_double_encoded = bool(DOUBLE_ENCODED.search(full_string))

    return {
        "path_length": len(path),
        "path_depth": path_depth,
        "query_length": len(query),
        "combined_entropy": round(combined_entropy, 3),
        "path_entropy": round(path_entropy, 3),
        "query_entropy": round(query_entropy, 3),
        "special_char_ratio": round(special_char_ratio, 3),
        "has_encoded_chars": has_encoded,
        "has_double_encoded": has_double_encoded,
    }

