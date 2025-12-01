# Evaluation Framework for Multi-Agent Security System

Based on Google ADK documentation and best practices, this document outlines comprehensive evaluation strategies for the distributed multi-agent security solution.

## Table of Contents

1. [ADK Evaluation Framework Overview](#adk-evaluation-framework-overview)
2. [Evaluation Levels](#evaluation-levels)
3. [Evaluation Criteria](#evaluation-criteria)
4. [Test Files vs Evalset Files](#test-files-vs-evalset-files)
5. [Multi-Agent Specific Evaluations](#multi-agent-specific-evaluations)
6. [Security Domain Specific Metrics](#security-domain-specific-metrics)
7. [Performance and Scalability](#performance-and-scalability)
8. [Safety and Reliability](#safety-and-reliability)
9. [Continuous Evaluation](#continuous-evaluation)
10. [Implementation Roadmap](#implementation-roadmap)

---

## ADK Evaluation Framework Overview

Google ADK provides built-in evaluation frameworks designed specifically for multi-agent systems:

### Key Components

1. **Test Files**: Individual test cases for simple agent-model interactions
   - Unit testing during development
   - Single-turn conversations
   - Tool use trajectory validation

2. **Evalset Files**: Complex multi-turn conversation scenarios
   - Integration testing
   - Multi-agent coordination
   - Real-world workflow simulation

3. **User Simulation**: Dynamic testing with AI-generated user inputs
   - Intent-based testing (not path-dependent)
   - Resilient to conversational variations
   - Focuses on achieving goals rather than specific prompts

---

## Evaluation Levels

### Level 1: Individual Agent Evaluation

**Purpose**: Validate each agent independently before integration testing.

#### Root Orchestrator Agent
- **Test Files**: Simple orchestration decisions
  - Can it correctly identify when to delegate to threat analysis?
  - Does it properly route incidents to incident response?
  - Session management and memory persistence

- **Evalset Files**: Multi-turn security event processing
  - Complex scenarios with multiple indicators
  - Escalation workflows
  - Memory retrieval across sessions

#### Threat Analysis Agent
- **Test Files**: Single indicator analysis
  - IP address analysis
  - Domain analysis
  - Hash analysis
  - URL analysis

- **Evalset Files**: Multi-indicator correlation
  - Related threat investigation
  - Historical context retrieval
  - Severity assessment accuracy

#### Incident Response Agent
- **Test Files**: Single incident handling
  - Incident creation
  - Playbook execution
  - Chronicle integration

- **Evalset Files**: Incident lifecycle management
  - Multi-stage incident response
  - SOAR automation validation
  - Incident closure workflows

### Level 2: Agent Pair Evaluation

**Purpose**: Validate A2A communication and coordination between agent pairs.

#### Root → Threat Analysis
- **Test Scenarios**:
  - Correct delegation of threat indicators
  - Proper parameter passing via A2A protocol
  - Response handling and error recovery
  - Timeout and retry mechanisms

#### Root → Incident Response
- **Test Scenarios**:
  - Incident escalation workflows
  - Context preservation across A2A calls
  - Response validation and error handling

### Level 3: Full System Integration

**Purpose**: End-to-end evaluation of the complete multi-agent workflow.

#### Complete Security Event Processing
- **Evalset Scenarios**:
  1. Simple threat → Analysis → No incident
  2. Critical threat → Analysis → Incident → Response
  3. Multiple concurrent events
  4. False positive handling
  5. Multi-stage attack detection

#### Distributed System Evaluation
- Network latency simulation
- Service availability (agent discovery)
- Failover scenarios
- Load testing with concurrent requests

---

## Evaluation Criteria

Based on ADK documentation, use these criteria:

### 1. Tool Trajectory Score

**What it measures**: Exact match of tool call sequences

**For your system**:
- **Root Agent**: Correct delegation decisions (threat_agent vs incident_agent)
- **Threat Agent**: Proper GTI API calls, BigQuery writes
- **Incident Agent**: Chronicle API calls, SOAR playbook triggers

**Implementation**:
```python
# Example: Validate tool call sequence
expected_trajectory = [
    "discover_agent('ThreatAnalysisAgent')",
    "invoke_agent('analyze_indicator', {...})",
    "store_threat_intelligence(...)"
]
actual_trajectory = capture_agent_tool_calls()
assert trajectory_match(expected_trajectory, actual_trajectory)
```

### 2. Response Match Score

**What it measures**: Similarity to reference responses using metrics like ROUGE-1

**For your system**:
- Threat severity classification accuracy
- Incident response action correctness
- Root agent decision rationale quality

**Metrics**:
- **ROUGE-1**: Unigram overlap
- **BLEU**: N-gram precision
- **Semantic Similarity**: Embedding-based comparison

### 3. Final Response Quality

**What it measures**: Language model evaluation based on predefined rubrics

**For your system**:
- **Threat Analysis Quality**:
  - Severity assessment accuracy (CRITICAL, HIGH, MEDIUM, LOW)
  - MITRE ATT&CK mapping correctness
  - Confidence score calibration

- **Incident Response Quality**:
  - Appropriate response actions
  - Playbook selection accuracy
  - Incident documentation completeness

- **Root Orchestrator Quality**:
  - Decision rationale clarity
  - Workflow coordination effectiveness
  - Error handling and recovery

### 4. Safety and Groundedness

**What it measures**: Detection of hallucinations, unsupported claims, unsafe actions

**For your system**:
- **Groundedness Checks**:
  - All threat intelligence claims backed by GTI data
  - Incident actions based on actual threat severity
  - No fabricated security events or indicators

- **Safety Checks**:
  - No unauthorized actions (e.g., blocking legitimate traffic)
  - Proper authentication before A2A calls
  - Secure handling of sensitive data

- **Hallucination Detection**:
  - Validate all API responses are real
  - Ensure BigQuery data exists before retrieval
  - Verify Chronicle incidents are actual events

---

## Test Files vs Evalset Files

### Test Files (Unit Testing)

**Structure**:
```yaml
# Example test file structure
test_name: "threat_analysis_ip_address"
user_query: "Analyze IP address 203.0.113.42"
expected_tool_calls:
  - tool: "analyze_indicator"
    parameters:
      indicator: "203.0.113.42"
      indicator_type: "ip"
expected_intermediate_responses:
  - "Querying Google Threat Intelligence..."
expected_final_response:
  - contains: "CRITICAL"
  - contains: "malicious"
  - contains: "MITRE"
```

**Use Cases**:
- Individual agent method testing
- Tool call validation
- Response format verification
- Error handling

**For Your System**:
- `test_threat_agent_ip_analysis.yaml`
- `test_threat_agent_domain_analysis.yaml`
- `test_incident_agent_create_incident.yaml`
- `test_root_agent_delegation.yaml`

### Evalset Files (Integration Testing)

**Structure**:
```yaml
# Example evalset file structure
evalset_name: "critical_threat_to_incident_workflow"
sessions:
  - session_id: "session_001"
    turns:
      - user: "Process security event: suspicious IP 203.0.113.42"
        expected_agent: "RootOrchestratorAgent"
        expected_delegation: "ThreatAnalysisAgent"
      - user: "Continue"
        expected_agent: "ThreatAnalysisAgent"
        expected_tool: "analyze_indicator"
      - user: "Continue"
        expected_agent: "RootOrchestratorAgent"
        expected_delegation: "IncidentResponseAgent"
      - user: "Continue"
        expected_agent: "IncidentResponseAgent"
        expected_tool: "handle_incident"
    expected_final_state:
      threat_severity: "CRITICAL"
      incident_created: true
      incident_id: "INC-.*"
```

**Use Cases**:
- Multi-agent workflows
- Session persistence
- Memory retrieval across agents
- Complex decision trees

**For Your System**:
- `evalset_critical_threat_workflow.yaml`
- `evalset_false_positive_handling.yaml`
- `evalset_multi_indicator_correlation.yaml`
- `evalset_incident_lifecycle.yaml`

---

## Multi-Agent Specific Evaluations

### 1. Agent Discovery and Registration

**Evaluation Points**:
- Can root agent discover sub-agents from Vertex AI Registry?
- Does discovery handle missing agents gracefully?
- Are agent capabilities correctly registered and queried?

**Test Scenarios**:
```python
# Test discovery success
def test_agent_discovery_success():
    registry.discover_agent("ThreatAnalysisAgent")
    assert endpoint is not None
    assert capabilities include "analyze_indicator"

# Test discovery failure
def test_agent_discovery_failure():
    result = registry.discover_agent("NonExistentAgent")
    assert result is None
    # Root agent should handle gracefully
```

### 2. A2A Protocol Communication

**Evaluation Points**:
- Correct HTTP request/response format
- Authentication and authorization
- Error handling and retries
- Timeout management

**Test Scenarios**:
```python
# Test successful A2A call
def test_a2a_successful_invocation():
    response = a2a_client.invoke_agent(
        endpoint="https://threat-agent.run.app",
        method="analyze_indicator",
        params={"indicator": "203.0.113.42"}
    )
    assert response["success"] == True
    assert "analysis" in response

# Test A2A timeout
def test_a2a_timeout():
    # Simulate slow response
    response = a2a_client.invoke_agent(..., timeout=1)
    assert response["success"] == False
    assert "timeout" in response["error"]
```

### 3. Workflow Orchestration

**Evaluation Points**:
- Correct delegation decisions
- Parallel vs sequential execution
- Error propagation and recovery
- Context preservation

**Test Scenarios**:
```python
# Test correct delegation
def test_threat_analysis_delegation():
    event = {"indicator": "203.0.113.42", "type": "ip"}
    result = root_agent.process_security_event(event)
    assert "threat_analysis" in result
    assert result["threat_analysis"]["agent"] == "ThreatAnalysisAgent"

# Test error recovery
def test_delegation_error_recovery():
    # Simulate threat agent failure
    mock_a2a_client.invoke_agent.side_effect = Exception("Service unavailable")
    result = root_agent.process_security_event(event)
    assert result["success"] == False
    assert "fallback" in result or "retry" in result
```

### 4. Memory and State Management

**Evaluation Points**:
- Session memory persistence
- BigQuery threat intelligence retrieval
- Incident history access
- Cross-agent memory sharing

**Test Scenarios**:
```python
# Test memory retrieval
def test_threat_history_retrieval():
    # Store threat
    threat_memory.store_threat("203.0.113.42", {...})
    # Retrieve in later session
    history = threat_memory.retrieve_threat_history("203.0.113.42")
    assert len(history) > 0

# Test cross-agent memory
def test_incident_context_preservation():
    # Root agent creates context
    context = root_agent.create_incident_context(event)
    # Incident agent receives context
    incident_agent.handle_incident(context)
    assert incident_agent.has_context(context)
```

---

## Security Domain Specific Metrics

### 1. Threat Detection Accuracy

**Metrics**:
- **True Positive Rate (TPR)**: Correctly identified threats
- **False Positive Rate (FPR)**: Benign indicators flagged as threats
- **Precision**: Of flagged threats, how many are actually threats
- **Recall**: Of actual threats, how many were detected

**Evaluation Method**:
```python
# Ground truth dataset
ground_truth = {
    "203.0.113.42": {"is_threat": True, "severity": "CRITICAL"},
    "198.51.100.1": {"is_threat": False, "severity": None},
    # ... more test cases
}

# Run evaluation
for indicator, truth in ground_truth.items():
    result = threat_agent.analyze_indicator(indicator)
    assert result["is_threat"] == truth["is_threat"]
    if truth["is_threat"]:
        assert result["severity"] == truth["severity"]
```

### 2. Incident Response Effectiveness

**Metrics**:
- **Mean Time to Detection (MTTD)**: Time from event to threat detection
- **Mean Time to Response (MTTR)**: Time from threat to incident response
- **Response Action Accuracy**: Correctness of automated actions
- **False Positive Incident Rate**: Incidents created for non-threats

**Evaluation Method**:
```python
# Measure response times
start_time = time.time()
threat_result = threat_agent.analyze_indicator(indicator)
detection_time = time.time() - start_time

start_time = time.time()
incident_result = incident_agent.handle_incident(threat_result)
response_time = time.time() - start_time

assert detection_time < 5.0  # MTTD < 5 seconds
assert response_time < 10.0  # MTTR < 10 seconds
```

### 3. MITRE ATT&CK Mapping Accuracy

**Metrics**:
- **Technique Mapping Accuracy**: Correct MITRE technique identification
- **Tactic Coverage**: Coverage of MITRE tactics
- **False Technique Assignments**: Incorrect technique mappings

**Evaluation Method**:
```python
# Ground truth MITRE mappings
mitre_ground_truth = {
    "malware_download": "T1105",
    "command_and_control": "T1071",
    # ...
}

# Evaluate mapping
result = threat_agent.analyze_indicator(indicator)
assert result["mitre_techniques"] in mitre_ground_truth.values()
```

### 4. Threat Intelligence Quality

**Metrics**:
- **GTI API Integration**: Successful API calls
- **Data Freshness**: Recency of threat intelligence
- **Confidence Score Calibration**: Accuracy of confidence scores

**Evaluation Method**:
```python
# Test GTI integration
result = threat_agent.analyze_indicator(indicator)
assert "gti_data" in result
assert result["gti_data"]["timestamp"] is recent
assert 0 <= result["confidence"] <= 100
```

---

## Performance and Scalability

### 1. Latency Metrics

**Key Metrics**:
- **End-to-End Latency**: Total time for security event processing
- **A2A Call Latency**: Time for inter-agent communication
- **API Call Latency**: Time for external API calls (GTI, Chronicle)

**Targets**:
- End-to-end: < 30 seconds for critical threats
- A2A calls: < 2 seconds
- GTI API: < 5 seconds
- Chronicle API: < 3 seconds

**Evaluation Method**:
```python
# Performance test
import time

start = time.time()
result = root_agent.process_security_event(event)
total_time = time.time() - start

assert total_time < 30.0
assert result["metrics"]["a2a_latency"] < 2.0
assert result["metrics"]["gti_latency"] < 5.0
```

### 2. Throughput Metrics

**Key Metrics**:
- **Events per Second**: Concurrent event processing capacity
- **Agent Scalability**: Performance under load
- **Resource Utilization**: CPU, memory, network usage

**Targets**:
- 10 concurrent events/second
- Linear scaling with agent instances
- < 80% resource utilization

**Evaluation Method**:
```python
# Load test
import concurrent.futures

events = [generate_event() for _ in range(100)]
start = time.time()

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(root_agent.process_security_event, events))

total_time = time.time() - start
throughput = len(events) / total_time

assert throughput >= 10.0  # 10 events/second
```

### 3. Scalability Evaluation

**Test Scenarios**:
- Single agent instance → Multiple instances
- Local deployment → Cloud Run deployment
- Single region → Multi-region deployment

**Metrics**:
- Response time degradation under load
- Error rate increase
- Resource cost per event

---

## Safety and Reliability

### 1. Error Handling

**Evaluation Points**:
- Agent unavailability handling
- API failure recovery
- Network timeout handling
- Invalid input validation

**Test Scenarios**:
```python
# Test agent failure
def test_threat_agent_failure():
    # Simulate threat agent down
    mock_a2a_client.invoke_agent.side_effect = ConnectionError()
    result = root_agent.process_security_event(event)
    # Should handle gracefully
    assert "error" in result or "fallback" in result

# Test invalid input
def test_invalid_indicator():
    result = threat_agent.analyze_indicator("invalid")
    assert result["success"] == False
    assert "error" in result
```

### 2. Security Validation

**Evaluation Points**:
- Authentication and authorization
- Data encryption in transit
- Secure credential handling
- Input sanitization

**Test Scenarios**:
```python
# Test authentication
def test_a2a_authentication():
    # Unauthenticated request should fail
    response = a2a_client.invoke_agent(..., auth_token=None)
    assert response["success"] == False
    assert response["error"] == "Unauthorized"

# Test input sanitization
def test_sql_injection_prevention():
    malicious_input = "'; DROP TABLE threats; --"
    result = threat_agent.analyze_indicator(malicious_input)
    # Should sanitize and handle safely
    assert "error" in result or result is safe
```

### 3. Data Integrity

**Evaluation Points**:
- BigQuery data consistency
- Memory persistence reliability
- Cross-agent data synchronization

**Test Scenarios**:
```python
# Test data persistence
def test_threat_intelligence_persistence():
    threat_agent.store_threat(indicator, data)
    # Retrieve from different session
    retrieved = threat_memory.retrieve_threat_history(indicator)
    assert retrieved == data
```

---

## Continuous Evaluation

### 1. CI/CD Integration

**Tools**:
- **AgentCI**: Automated ADK agent evaluation
  - Discovers and evaluates agents
  - Provides accuracy, safety, performance testing
  - No code modifications required

**Integration**:
```yaml
# Example CI/CD pipeline
stages:
  - test:
      - pytest tests/
      - adk evaluate test_files/
  - integration:
      - adk evaluate evalsets/
  - performance:
      - load_test.py
  - safety:
      - safety_scan.py
```

### 2. Monitoring and Observability

**Metrics to Monitor**:
- Agent response times
- Error rates
- A2A call success rates
- Threat detection accuracy (over time)
- Resource utilization

**Tools**:
- Cloud Run metrics
- BigQuery query logs
- Custom application metrics
- Vertex AI monitoring

### 3. A/B Testing

**Use Cases**:
- Model version comparison (gemini-2.5-pro vs gemini-pro)
- Agent logic improvements
- Workflow optimization

**Method**:
```python
# A/B test framework
def ab_test_event(event):
    # Route to both versions
    result_a = root_agent_v1.process_security_event(event)
    result_b = root_agent_v2.process_security_event(event)
    
    # Compare metrics
    compare_results(result_a, result_b)
```

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)
1. **Create Test Files**
   - Individual agent test files
   - Basic tool trajectory tests
   - Response format validation

2. **Set Up Evaluation Infrastructure**
   - ADK evaluation framework integration
   - Test file parser
   - Result collection system

### Phase 2: Integration (Week 3-4)
1. **Create Evalset Files**
   - Multi-agent workflow scenarios
   - Complex security event processing
   - Error recovery scenarios

2. **Implement Evaluation Metrics**
   - Tool trajectory scoring
   - Response match scoring
   - Safety and groundedness checks

### Phase 3: Domain-Specific (Week 5-6)
1. **Security Metrics**
   - Threat detection accuracy
   - Incident response effectiveness
   - MITRE ATT&CK mapping validation

2. **Performance Testing**
   - Latency benchmarks
   - Throughput testing
   - Scalability evaluation

### Phase 4: Continuous (Ongoing)
1. **CI/CD Integration**
   - Automated test execution
   - Performance regression detection
   - Safety monitoring

2. **Production Monitoring**
   - Real-time metrics collection
   - Anomaly detection
   - Continuous improvement

---

## Evaluation Checklist

### Pre-Deployment
- [ ] All test files pass
- [ ] All evalset files pass
- [ ] Performance targets met
- [ ] Safety checks validated
- [ ] Security validation complete

### Post-Deployment
- [ ] Monitoring dashboards configured
- [ ] Alert thresholds set
- [ ] Baseline metrics established
- [ ] Evaluation schedule defined

### Ongoing
- [ ] Weekly evaluation runs
- [ ] Monthly performance reviews
- [ ] Quarterly accuracy assessments
- [ ] Continuous safety monitoring

---

## References

- [Google ADK Evaluation Documentation](https://google.github.io/adk-docs/evaluate/)
- [Multi-Agent Systems in ADK](https://google.github.io/adk-docs/agents/multi-agents/)
- [User Simulation in ADK](https://developers.googleblog.com/en/announcing-user-simulation-in-adk-evaluation/)
- [AgentCI Integration](https://agent-ci.com/docs/integration/google-adk)

---

## Next Steps

1. **Review this framework** with your team
2. **Prioritize evaluation areas** based on business needs
3. **Create initial test files** for critical workflows
4. **Set up evaluation infrastructure** (ADK framework, CI/CD)
5. **Establish baseline metrics** from current system
6. **Implement continuous evaluation** process

This framework provides a comprehensive approach to evaluating your multi-agent security system while aligning with Google ADK best practices and security domain requirements.


