import os
import json
import requests
from google.adk.agents import Agent
from datetime import datetime

# --- Tool Definition ---
def lookup_threat_indicator(indicator: str, indicator_type: str = "ip") -> dict:
    """
    Checks an indicator (IP/Domain/Hash) against Threat Intelligence.
    Uses VirusTotal API if available, otherwise returns simulated data.
    """
    api_key = os.getenv("VT_APIKEY")
    
    print(f"\n🔎 [Tool] Checking Threat Intel for: {indicator} ({indicator_type})...")

    # 1. REAL MODE: Try VirusTotal API
    if api_key and api_key != "your-vt-api-key":
        try:
            # Simple API call to VirusTotal (Mocking the full MCP server for simplicity)
            url = f"https://www.virustotal.com/api/v3/{indicator_type}_addresses/{indicator}" if indicator_type == "ip" else \
                  f"https://www.virustotal.com/api/v3/domains/{indicator}"
            
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "source": "VirusTotal (Real)",
                    "malicious_score": stats.get("malicious", 0),
                    "suspicious_score": stats.get("suspicious", 0),
                    "reputation": data.get("reputation", 0),
                    "tags": data.get("tags", []),
                    "whois": data.get("whois", "N/A")[:100]  # Truncate for brevity
                }
        except Exception as e:
            print(f"⚠️ API Error: {e}. Falling back to simulation.")

    # 2. SIMULATION MODE (Hackathon Safety Net)
    # Returns data matching your PDF scenarios
    print("⚡ [Tool] Using Simulated Knowledge Base")
    
    if indicator == "203.0.113.42":
        return {
            "source": "GTI Simulation",
            "verdict": "CRITICAL",
            "threat_actor": "APT28 (Fancy Bear)",
            "malware_family": "Cobalt Strike",
            "confidence": 95,
            "description": "Known Command & Control (C2) beacon node."
        }
    elif indicator == "evil-phishing.com":
        return {
            "source": "GTI Simulation",
            "verdict": "HIGH",
            "threat_type": "Phishing",
            "confidence": 88,
            "description": "Domain hosting credential harvesting pages."
        }
    
    return {"verdict": "BENIGN", "confidence": 0, "description": "No threats found."}

# --- Agent Definition ---
class ThreatAnalysisAgent:
    def __init__(self, project_id: str, model_name: str = "gemini-1.5-flash-001"):
        self.agent = Agent(
            name="threat_analyst",
            model=model_name,
            intro="""You are an expert Cyber Threat Intelligence Analyst. 
            Your job is to investigate security indicators (IPs, Domains, Hashes).
            
            ALWAYS use the 'lookup_threat_indicator' tool first.
            
            Output your final answer in this specific JSON format:
            {
                "verdict": "CRITICAL|HIGH|MEDIUM|LOW",
                "confidence": <0-100>,
                "threat_actor": "Name or Unknown",
                "summary": "One sentence summary of the threat"
            }
            """,
            tools=[lookup_threat_indicator]
        )

    def analyze(self, indicator: str):
        """Run the analysis workflow"""
        prompt = f"Analyze this indicator: {indicator}"
        response = self.agent.get_response(prompt)
        return response.text

# --- Quick Test ---
if __name__ == "__main__":
    # Load env vars
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    
    # Initialize
    analyst = ThreatAnalysisAgent(project_id)
    
    # Test Scenario
    test_ip = "203.0.113.42"
    print(f"🤖 Agent starting investigation on {test_ip}...")
    result = analyst.analyze(test_ip)
    print(f"\n📄 Final Report:\n{result}")