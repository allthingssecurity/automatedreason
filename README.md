# 🧠🛡️ Neuro-Symbolic Automated Reasoning for Cloud Security

A sophisticated neuro-symbolic AI system that combines Large Language Models (LLMs) with formal symbolic reasoning engines for automated cloud security policy validation.

## 🚀 Features

### 1. **Kubernetes Policy Validation with Rego/OPA**
- Neural AI generates Kubernetes manifests using OpenAI GPT
- Symbolic validation using Open Policy Agent (OPA) with Rego policies
- Generator-Verifier loop for iterative improvement and repair
- Real-time WebSocket updates for UI feedback

### 2. **XSUAA Security Analysis**
- Static security analysis for SAP XSUAA (Identity service) policies
- Natural language queries about access control and compliance
- Neural translation of queries to logical representations
- Symbolic evaluation against xs-security.json configurations

### 3. **Real Cloud-Native 12-Factor App Validator**
- **Actual** OpenAI LLM calls for parsing application artifacts
- **Real** Microsoft Z3 SMT solver for constraint satisfaction
- 12-Factor App principles encoded as Z3 boolean constraints
- Validates SAP BTP applications against cloud-native best practices

## 🏗️ Architecture

```
🧠 Neural Engine (LLM)     +     🛡️ Symbolic Engine (Formal Logic)
├── OpenAI GPT-4o-mini           ├── Open Policy Agent (OPA/Rego)
├── Manifest Generation          ├── Microsoft Z3 SMT Solver
├── Fact Extraction              ├── Constraint Satisfaction
└── Natural Language             └── Mathematical Proof
```

## 🛠️ Technical Stack

- **Backend**: Python Flask with WebSocket support
- **Neural AI**: OpenAI GPT-4o-mini API
- **Symbolic Engines**: 
  - OPA (Open Policy Agent) with Rego
  - Microsoft Z3 SMT Solver
- **Frontend**: HTML5/JavaScript with real-time updates
- **Security**: XSUAA policy analysis, Kubernetes security validation

## 🔧 Setup

1. **Install Dependencies**:
   ```bash
   pip install flask flask-socketio openai pyyaml z3-solver
   ```

2. **Install OPA Binary**:
   ```bash
   # Download OPA binary to ~/bin/opa
   # The app will automatically detect it
   ```

3. **Set OpenAI API Key**:
   ```bash
   export OPENAI_API_KEY="your-openai-api-key-here"
   ```

4. **Run Application**:
   ```bash
   python app.py
   # Server starts on http://localhost:9000
   ```

## 🎯 Usage

### Kubernetes Policy Validation
- Access: `http://localhost:9000/`
- Upload K8s manifests for SAP-specific policy validation
- Uses generator-verifier loop for automatic repairs

### XSUAA Security Analysis  
- Access: `http://localhost:9000/test_xsuaa`
- Upload xs-security.json configurations
- Ask natural language questions about access control

### Real Cloud-Native Validation
- Access: `http://localhost:9000/test_real_cloud_native`
- Upload application artifacts (mta.yaml, Dockerfile, etc.)
- Get real LLM + Z3 SMT solver analysis

## 📊 Example Results

### Z3 SMT Solver Output
```json
{
  "violations": [{
    "factor_number": "II",
    "principle_name": "Store config in the environment", 
    "z3_model": "[fact_config_hardcoded_0 = True, violates_factor_ii = True]",
    "suggested_fix": "Move all configuration to environment variables"
  }],
  "compliance_score": 0.9,
  "method": "REAL_NEURO_SYMBOLIC"
}
```

## 🔬 Research Applications

This system demonstrates:
- **Neuro-Symbolic AI**: Combining neural and symbolic reasoning
- **Formal Verification**: Mathematical proofs of security violations  
- **Automated Security**: AI-driven policy compliance checking
- **Cloud-Native Validation**: 12-Factor App principle enforcement

## 📁 Key Files

- `app.py` - Main Flask application with all endpoints
- `real_cloud_native_validator.py` - Real LLM + Z3 SMT validator
- `xsuaa_policy_engine.py` - XSUAA neuro-symbolic analyzer  
- `policies/opa/sap-k8s-policies.rego` - Kubernetes security policies
- `test_*.html` - UI interfaces for different validators

## 🧠 Neural + Symbolic Processing

The system implements true neuro-symbolic AI where:
1. **LLMs extract facts** from unstructured application code
2. **Symbolic solvers verify** these facts against formal constraints
3. **Mathematical proof** provides explainable security violations
4. **No hallucinations** - only logically provable results

## 🔐 Security Features

- API key protection with .gitignore
- Defensive security focus only
- No malicious code generation
- Formal verification prevents false positives
- Explainable AI with constraint models

---

**Note**: Replace `your-openai-api-key-here` with actual OpenAI API key in test files before running.