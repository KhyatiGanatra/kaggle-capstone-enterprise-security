#!/usr/bin/env python3
"""
Test script to verify A2A response unwrapping logic
"""

import json

# Simulate the A2A wrapped response (what we get from Cloud Run)
wrapped_response = {
    "success": True,
    "agent": "ThreatAnalysisAgent",
    "method": "analyze_indicator",
    "result": {
        "success": True,
        "analysis": {
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "severity": "INFO",
            "confidence": 40,
            "detection_ratio": "0/95"
        },
        "mode": {
            "is_live": True,
            "source": "VirusTotal GTI"
        }
    }
}

print("=" * 80)
print("TEST: A2A Response Unwrapping Logic")
print("=" * 80)

print("\n1. WRAPPED RESPONSE (what A2A server returns):")
print(json.dumps(wrapped_response, indent=2))

# Apply the unwrapping logic (same as in root_agent.py:429-436)
result = wrapped_response

if isinstance(result, dict) and 'result' in result:
    print("\n2. ✓ Found 'result' key - unwrapping...")
    unwrapped = result['result']
else:
    print("\n2. ✗ No 'result' key found - using as-is")
    unwrapped = result

print("\n3. UNWRAPPED RESPONSE:")
print(json.dumps(unwrapped, indent=2))

# Test accessing the data (same as in root_agent.py:721-722)
print("\n4. ACCESSING DATA:")
analysis = unwrapped.get('analysis', {})
mode = unwrapped.get('mode', {})

print(f"   - analysis keys: {list(analysis.keys())}")
print(f"   - mode keys: {list(mode.keys())}")

# Extract specific fields (same as in root_agent.py:728-731)
indicator = analysis.get('indicator', 'Unknown')
severity = analysis.get('severity', 'UNKNOWN')
confidence = analysis.get('confidence', 'N/A')
detection_ratio = analysis.get('detection_ratio', 'N/A')
source = mode.get('source', 'Unknown')

print("\n5. EXTRACTED VALUES:")
print(f"   - Indicator: {indicator}")
print(f"   - Severity: {severity}")
print(f"   - Confidence: {confidence}%")
print(f"   - Detection Ratio: {detection_ratio}")
print(f"   - Source: {source}")

# Check if we got real values or defaults
print("\n6. VALIDATION:")
if indicator == "8.8.8.8" and severity == "INFO" and confidence == 40:
    print("   ✅ SUCCESS - All values extracted correctly!")
    print("   ✅ The unwrapping logic works!")
else:
    print("   ❌ FAILED - Got default values instead of real data")
    print(f"      Expected: indicator=8.8.8.8, severity=INFO, confidence=40")
    print(f"      Got: indicator={indicator}, severity={severity}, confidence={confidence}")

print("\n" + "=" * 80)

# Now test WITHOUT unwrapping (to show the bug)
print("\nCOMPARISON: What happens WITHOUT unwrapping:")
print("=" * 80)

buggy_result = wrapped_response  # Don't unwrap
buggy_analysis = buggy_result.get('analysis', {})  # This will return {}
buggy_mode = buggy_result.get('mode', {})  # This will also return {}

print(f"\nbuggy_analysis: {buggy_analysis}")
print(f"buggy_mode: {buggy_mode}")

buggy_indicator = buggy_analysis.get('indicator', 'Unknown')
buggy_severity = buggy_analysis.get('severity', 'UNKNOWN')

print(f"\nExtracted (buggy):")
print(f"   - Indicator: {buggy_indicator} (should be 8.8.8.8)")
print(f"   - Severity: {buggy_severity} (should be INFO)")
print(f"\n   ❌ Without unwrapping, we get defaults!")
print(f"   ❌ This is why you saw 'any any' in the UI!")

print("\n" + "=" * 80)
