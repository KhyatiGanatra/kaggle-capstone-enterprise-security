# Argus Multi-Agent Security Platform - Architecture & Response Flow Analysis

**Date:** 2025-11-30
**Status:** Issue Diagnosed - Response flow broken between sub-agents and UI

---

## System Overview

Argus is a multi-agent security platform built with Google ADK (Agent Development Kit) that provides intelligent threat analysis and incident response capabilities.

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    UI Layer (Streamlit)                      │
│                     ui_cloudrun.py                           │
│                                                              │
│  - User interface for security operations                   │
│  - Communicates with Root Agent via A2A protocol over HTTPS │
│  - Displays threat analysis and incident response results   │
└───────────────────┬─────────────────────────────────────────┘
                    │ A2A/HTTPS
                    │ POST /a2a/invoke
                    │ {"agent": "RootOrchestratorAgent",
                    │  "method": "chat",
                    │  "params": {"user_message": "..."}}
                    │
┌───────────────────▼─────────────────────────────────────────┐
│                    Root Orchestrator Agent                   │
│                   agents/root_agent.py                       │
│                                                              │
│  - Central coordinator for security operations              │
│  - ADK agent with delegator tools                          │
│  - Tools: analyze_threat, respond_to_incident,             │
│          execute_quick_action                               │
│  - Routes requests to specialized sub-agents                │
└──┬────────────────────────────────────┬────────────────────┘
   │ Tool Call                          │ Tool Call
   │ analyze_threat()                   │ respond_to_incident()
   │                                    │
┌──▼──────────────────┐             ┌──▼─────────────────────┐
│  Threat Agent       │             │  Incident Agent        │
│  threat_agent.py    │             │  incident_agent.py     │
│                     │             │                        │
│  - GTI MCP tools    │             │  - Simulated SOAR      │
│  - VirusTotal API   │             │  - create_case()       │
│  - IP/Domain/Hash   │             │  - block_ip()          │
│    analysis         │             │  - isolate_endpoint()  │
│  - Returns JSON     │             │  - disable_user()      │
└─────────────────────┘             └────────────────────────┘
```

---

## Data Flow - Expected vs Actual

### Expected Flow (How it Should Work)

```
1. User enters: "Analyze 8.8.8.8" in UI
   └→ ui_cloudrun.py:557

2. UI calls Root Agent via A2A:
   POST https://root-agent-url/a2a/invoke
   Body: {
     "agent": "RootOrchestratorAgent",
     "method": "chat",
     "params": {"user_message": "Analyze 8.8.8.8"}
   }
   └→ ui_cloudrun.py:557-562

3. A2A Server receives request:
   └→ shared/communication/a2a_server_fastapi.py:64

4. A2A Server calls chat() method:
   └→ agents/root_agent.py:584

5. chat() calls run_agent_sync() with ADK agent:
   └→ agents/root_agent.py:613

6. ADK Agent processes the message:
   - Sees "8.8.8.8" in user message
   - System prompt instructs: "IP address → call analyze_threat()"
   - Calls tool: analyze_threat(indicator="8.8.8.8", indicator_type="ip")
   └→ agents/root_agent.py:284 (tool function)

7. analyze_threat() tool delegates to Threat Agent:
   └→ agents/root_agent.py:299 → _call_threat_agent()

8. Threat Agent analyzes via VirusTotal GTI MCP:
   └→ agents/threat_agent.py:501 → analyze_indicator()
   Returns: {
     "success": True,
     "analysis": {
       "indicator": "8.8.8.8",
       "severity": "HIGH",
       "confidence": 85,
       "detection_ratio": "15/92",
       ...
     }
   }

9. Tool result flows back to ADK agent as JSON string:
   └→ agents/root_agent.py:301 (return json.dumps(result))

10. ⚠️ THIS IS WHERE IT BREAKS ⚠️
    ADK Agent should generate a FINAL MODEL RESPONSE that:
    - Takes the tool result JSON
    - Formats it according to system prompt template
    - Returns formatted markdown response

    BUT: The model is NOT generating this final response!

11. run_agent_sync() captures events:
    - Tool call event: ✓ (captured)
    - Tool result event: ✓ (captured)
    - Final model text: ✗ (MISSING!)
    └→ agents/root_agent.py:38-140

12. chat() returns: {"text": "", "trace": [...]}
    └→ agents/root_agent.py:650

13. A2A wraps response:
    {
      "success": True,
      "result": {"text": "", "trace": [...]}
    }
    └→ a2a_server_fastapi.py:204-209

14. UI receives empty text:
    response_text = result.get("result", {}).get("text", "")
    # response_text == "" ❌
    └→ ui_cloudrun.py:563
```

### What's Visible in ADK Web Traces

The ADK Web UI (`/web` endpoint) shows:
- ✓ User message received
- ✓ Tool call: `analyze_threat(indicator="8.8.8.8")`
- ✓ Tool response: Full JSON with analysis data
- ✗ NO FINAL MODEL RESPONSE

This confirms:
1. The root agent IS calling sub-agents correctly
2. Sub-agents ARE working and returning data
3. Tool calls and responses ARE visible in traces
4. BUT the final model turn is missing

---

## The Root Cause

### Issue Location
`agents/root_agent.py` - Lines 38-140 (`run_agent_sync` function) and Agent configuration at Line 202-207

### Problem Description

The ADK agent is configured but not generating a final text response after tool execution completes. The event stream contains:

1. `GenerateContentRequest` - User message
2. `FunctionCall` events - Tool executions ✓
3. `FunctionResponse` events - Tool results ✓
4. **MISSING:** Final `Content` event with model's formatted response

### Why This Happens

Possible causes:

1. **No explicit "continue generation" signal**: After tools return, the agent might need configuration to generate a final turn

2. **Event loop terminates too early**: The `async for event in agent.run_async(context)` loop might be ending before the final model turn

3. **Model needs explicit instruction**: The system prompt might need to be more explicit about ALWAYS generating a final response after tools

4. **Missing generation config**: The ADK Agent might need generation parameters like:
   ```python
   generation_config = {
       "response_required_after_tools": True,
       "max_output_tokens": 2048,
   }
   ```

---

## Code Locations

### Key Files

1. **UI Entry Point**
   - File: `ui_cloudrun.py`
   - Function: `invoke_a2a_agent()` at line 221
   - Calls: `/a2a/invoke` endpoint

2. **Root Agent**
   - File: `agents/root_agent.py`
   - Class: `RootOrchestratorAgent`
   - Key Methods:
     - `chat()` - Line 584: Main entry point
     - `run_agent_sync()` - Line 38: Runs ADK agent and captures events
     - `_create_delegation_tools()` - Line 281: Creates tool functions
     - `_call_threat_agent()` - Line 441: Delegates to threat agent
     - `_call_incident_agent()` - Line 480: Delegates to incident agent

3. **Threat Agent**
   - File: `agents/threat_agent.py`
   - Method: `analyze_indicator()` - Line 501
   - Returns: Structured JSON with threat analysis

4. **Incident Agent**
   - File: `agents/incident_agent.py`
   - Methods: `handle_incident()`, `execute_action()`
   - Returns: Structured JSON with incident response

5. **A2A Server**
   - File: `shared/communication/a2a_server_fastapi.py`
   - Route: `/a2a/invoke` - Line 64
   - Calls registered methods and wraps responses

---

## Attempted Fixes (from git history)

### Commit d9bff03: "Fix run_agent_sync to capture final model response correctly"

**What was changed:**
- Modified `run_agent_sync()` to keep LAST text response instead of concatenating all
- Added logic to skip `function_response` parts (tool results)
- Added debug logging to track text capture

**Why it didn't fully solve the problem:**
- The fix improved text capture logic ✓
- But the underlying issue remains: **the model isn't generating a final text** ✗
- You can't capture text that was never generated!

### Commit 76a962a: "Fix asyncio event loop conflict in run_agent_sync"

**What was changed:**
- Added `nest_asyncio.apply()` to handle Streamlit + ADK conflicts

**Result:**
- Fixed event loop issues ✓
- But didn't address the missing final response

---

## The Fix (To Be Implemented)

### Option 1: Add Generation Config to ADK Agent

```python
# In agents/root_agent.py, line 202
self.agent = adk.Agent(
    name="RootOrchestratorAgent",
    model="gemini-2.0-flash",
    instruction=self._get_system_prompt(),
    tools=[...],
    generation_config={
        # Force model to always generate after tools
        "candidate_count": 1,
        "max_output_tokens": 2048,
    }
)
```

### Option 2: Modify System Prompt to Be More Explicit

Add to the system prompt:

```
CRITICAL WORKFLOW:
1. When user provides a request, call the appropriate tool
2. WAIT for the tool to return results
3. ALWAYS generate a final response using the template
4. NEVER end the conversation after calling a tool
5. ALWAYS provide formatted output to the user
```

### Option 3: Manual Response Generation (Fallback)

If ADK agent returns no text, manually format the tool results:

```python
# In chat() method after run_agent_sync()
if not response_text or not response_text.strip():
    # Model didn't generate response - manually format tool results
    if trace and any(t.get("type") == "tool_call" for t in trace):
        # Extract tool results from trace and format them
        response_text = self._format_tool_results(trace)
```

### Option 4: Two-Turn Approach

Call the agent twice:
1. First turn: User message → Tool calls
2. Second turn: Tool results → Generate final response

---

## Testing Plan

After implementing the fix:

1. **Local Test:**
   ```bash
   python test_root_agent.py
   ```
   - Should show full formatted response
   - Response should include analysis data from sub-agents

2. **Web UI Test:**
   ```bash
   streamlit run ui_cloudrun.py
   ```
   - Enter: "Analyze 8.8.8.8"
   - Should display formatted markdown response in chat

3. **ADK Web Trace Test:**
   - Visit `http://localhost:8080/web`
   - Check session events
   - Should see final model response in event stream

4. **Verify Response Structure:**
   ```json
   {
     "success": true,
     "result": {
       "text": "### 🛡️ Security Assessment\n\n**Status:** Analysis Complete...",
       "trace": [...]
     }
   }
   ```

---

## Next Steps

1. ✅ Document architecture (this file)
2. ⏳ Test different fix options
3. ⏳ Implement the working fix
4. ⏳ Verify in all scenarios (UI, A2A, Web traces)
5. ⏳ Update deployment documentation
6. ⏳ Commit and deploy to Cloud Run

---

## References

- ADK Documentation: https://cloud.google.com/vertex-ai/generative-ai/docs/agent-builder
- Tool Calling Guide: https://ai.google.dev/gemini-api/docs/function-calling
- Streamlit App: `ui_cloudrun.py:498-568`
- Root Agent: `agents/root_agent.py:584-650`
- A2A Protocol: `shared/communication/a2a_server_fastapi.py`
