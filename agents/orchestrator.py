import os
from google.adk.agents import Agent

# Import the sub-agent we already built
from agents.threat_agent import ThreatAnalysisAgent

class RootOrchestratorAgent:
    def __init__(self, project_id: str):
        self.project_id = project_id
        
        # Initialize Sub-Agents
        print("🤖 [Orchestrator] Waking up sub-agents...")
        self.threat_analyst = ThreatAnalysisAgent(project_id)
        
        # We will build this next, but let's placeholder it for now
        self.incident_responder = None 

        # The Boss Agent (Gemini 1.5 Pro is better for complex reasoning)
        self.agent = Agent(
            name="root_orchestrator",
            model="gemini-1.5-pro-001",
            intro="""You are the Security Operations Manager (SOC Lead).
            Your goal is to coordinate a response to security alerts.
            
            You have a team of agents:
            1. Threat Analyst: Can investigate IPs, Domains, and Hashes.
            
            PROTOCOL:
            1. When you receive an alert, ask the Threat Analyst to investigate the indicator.
            2. Review their report.
            3. If the Threat Analyst says 'CRITICAL' or 'HIGH', you must plan a response.
            
            Always output your thought process clearly.
            """
        )

    def process_alert(self, alert_data: dict):
        """
        Main entry point for the system.
        alert_data example: {"indicator": "1.2.3.4", "type": "ip"}
        """
        print(f"\n🚨 [Orchestrator] Received Alert: {alert_data}")
        
        # Step 1: Delegate to Threat Analyst
        indicator = alert_data.get("indicator")
        print(f"👉 [Orchestrator] Delegating {indicator} to Threat Analyst...")
        
        # Direct Agent-to-Agent call (Function calling in Python)
        threat_report = self.threat_analyst.analyze(indicator)
        
        print(f"📝 [Orchestrator] Reviewing Threat Report...")
        print(threat_report)
        
        # Step 2: Decide next steps (Simulated logic for now)
        # In the next step, we will have the agent strictly parse this JSON.
        if "CRITICAL" in threat_report or "HIGH" in threat_report:
            return {
                "status": "ESCALATED",
                "reason": "Threat Analyst confirmed malicious activity.",
                "report": threat_report
            }
        else:
            return {
                "status": "CLOSED",
                "reason": "Threat Analyst returned benign verdict."
            }

# --- Quick Test ---
if __name__ == "__main__":
    project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    
    # Simulate a "Real" Alert coming from a SIEM
    sample_alert = {
        "id": "ALERT-999",
        "indicator": "203.0.113.42", # The malicious IP from our scenario
        "type": "ip",
        "timestamp": "2025-11-22T10:00:00Z"
    }
    
    boss = RootOrchestratorAgent(project_id)
    final_decision = boss.process_alert(sample_alert)
    
    print("\n⚖️ [Orchestrator] Final Decision:")
    print(final_decision)