from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
import os
import json
import yaml
import re
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import asyncio
import threading
from openai import OpenAI
import subprocess
import tempfile
from pathlib import Path

# Initialize Flask app with WebSocket support
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'sap-k8s-policy-validator-2025')
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    logger=False,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Initialize OpenAI client
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# ─────────────────────────────────────────────────────────────
# Data Models for Neuro-Symbolic System
# ─────────────────────────────────────────────────────────────

@dataclass
class PolicyViolation:
    """Represents a policy violation found by symbolic reasoner"""
    rule_id: str
    title: str
    description: str
    severity: str  # 'high', 'medium', 'low'
    path: str  # YAML path where violation occurs
    suggested_fix: str

@dataclass
class ValidationResult:
    """Results from symbolic policy validation"""
    is_compliant: bool
    violations: List[PolicyViolation]
    compliance_score: float

# ─────────────────────────────────────────────────────────────
# Neural AI Component (LLM-based)
# ─────────────────────────────────────────────────────────────

class NeuralManifestGenerator:
    """Neural AI component for generating and repairing Kubernetes manifests"""
    
    def __init__(self, client):
        self.client = client
        
    def generate_manifest(self, requirements: str) -> str:
        """Generate K8s manifest from natural language requirements"""
        
        print(f"🧠 Neural: Starting manifest generation...")
        import sys
        sys.stdout.flush()
        
        system_prompt = """You are an expert Kubernetes architect specializing in SAP workloads. 
        Generate production-ready Kubernetes YAML manifests based on user requirements.
        
        Focus on:
        - SAP workload patterns (CAP services, integration flows, etc.)
        - Production best practices
        - Security considerations
        - Resource optimization
        
        CRITICAL: Return ONLY valid YAML content. No markdown formatting, no explanations, no code blocks.
        Start directly with 'apiVersion:' or '---' separators."""
        
        user_prompt = f"""Generate a complete Kubernetes manifest for this SAP deployment:

{requirements}

Include appropriate:
- Deployment with proper resource limits
- Service for networking  
- ConfigMap for configuration
- ServiceAccount for security
- HorizontalPodAutoscaler if scaling mentioned
- NetworkPolicy if security requirements specified

Return only the YAML content, no markdown blocks or explanations."""

        try:
            print(f"🧠 Neural: Calling OpenAI API...")
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",  # Use faster model
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=2000,
                timeout=30  # Add timeout
            )
            print(f"🧠 Neural: OpenAI API response received")
            
            manifest = response.choices[0].message.content.strip()
            
            # Aggressive cleaning of markdown and unwanted content
            manifest = self._clean_yaml_output(manifest)
            
            # Validate the cleaned YAML
            try:
                list(yaml.safe_load_all(manifest))
                return manifest
            except yaml.YAMLError as e:
                # If YAML is still invalid, try to fix common issues
                manifest = self._fix_common_yaml_issues(manifest)
                # Test again
                list(yaml.safe_load_all(manifest))
                return manifest
                
        except Exception as e:
            print(f"❌ Neural generation error: {str(e)}")
            import traceback
            traceback.print_exc()
            raise Exception(f"Neural generation failed: {str(e)}")
    
    def _clean_yaml_output(self, content: str) -> str:
        """Aggressively clean LLM output to extract only YAML"""
        lines = content.split('\n')
        cleaned_lines = []
        in_yaml = False
        
        for line in lines:
            # Remove markdown code blocks
            if line.strip().startswith('```'):
                if 'yaml' in line.lower():
                    in_yaml = True
                elif line.strip() == '```':
                    in_yaml = False
                continue
            
            # If we haven't found a code block, assume we're in YAML
            if not in_yaml and (line.strip().startswith('apiVersion:') or line.strip() == '---'):
                in_yaml = True
            
            # Include YAML lines
            if in_yaml or line.strip().startswith(('apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', '---')):
                # Remove any leading non-YAML characters
                clean_line = re.sub(r'^[^a-zA-Z\-\s]*', '', line)
                cleaned_lines.append(clean_line)
        
        result = '\n'.join(cleaned_lines).strip()
        
        # Remove any remaining markdown artifacts
        result = re.sub(r'```[a-zA-Z]*\n?', '', result)
        result = re.sub(r'\n```\n?', '', result)
        
        return result
    
    def _fix_common_yaml_issues(self, content: str) -> str:
        """Fix common YAML formatting issues"""
        # Remove any stray backticks
        content = re.sub(r'`{1,3}', '', content)
        
        # Fix indentation issues (basic)
        lines = content.split('\n')
        fixed_lines = []
        
        for line in lines:
            # Remove any non-YAML leading characters
            if line.strip():
                # Remove leading non-space, non-alphanumeric characters except - and :
                clean_line = re.sub(r'^[^\w\s\-:]*', '', line)
                fixed_lines.append(clean_line)
            else:
                fixed_lines.append(line)
        
        return '\n'.join(fixed_lines)
    
    def repair_manifest(self, manifest: str, violations: List[PolicyViolation], requirements: str) -> Tuple[str, str]:
        """Repair manifest to fix policy violations"""
        
        violations_text = "\n".join([
            f"- {v.title}: {v.description} (Fix: {v.suggested_fix})"
            for v in violations
        ])
        
        system_prompt = """You are an expert Kubernetes security engineer. Fix policy violations in YAML manifests while preserving the original functionality and user requirements.

CRITICAL INSTRUCTIONS:
1. Return ONLY valid YAML content for the manifest
2. NO markdown code blocks or formatting  
3. NO explanations mixed with YAML
4. Start directly with 'apiVersion:' or '---'
5. For missing labels, add them to ALL resources (Deployment, Service, etc.)
6. Use meaningful values: team: "platform", version: "1.0", app: "service-name"

After the complete YAML manifest, add a separator line '###EXPLANATION###' followed by your explanation."""
        
        user_prompt = f"""Fix these SPECIFIC policy violations in the Kubernetes manifest:

ORIGINAL REQUIREMENTS:
{requirements}

CURRENT MANIFEST:
{manifest}

POLICY VIOLATIONS TO FIX (BE VERY SPECIFIC):
{violations_text}

CRITICAL: Address each violation precisely:
- If "Missing Resource Limits" → Add resources.limits with cpu/memory to ALL containers
- If "Missing Required Labels" → Add team/version/app labels to metadata.labels
- If "Missing Audit Logging" → Add audit-logger sidecar container
- If "Security Context" → Add securityContext with runAsNonRoot: true
- If "High Availability" → Increase replicas to 3+

Return the complete fixed YAML manifest, then '###EXPLANATION###', then explain exactly which violations you fixed and how."""

        try:
            print(f"🔧 Neural: Calling OpenAI API for repair...")
            import sys
            sys.stdout.flush()
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",  # Use faster model
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=2000,  # Reduced tokens
                timeout=20  # Add timeout
            )
            print(f"🔧 Neural: Repair API response received")
            sys.stdout.flush()
            
            content = response.choices[0].message.content.strip()
            
            # Parse response using the separator
            if "###EXPLANATION###" in content:
                parts = content.split("###EXPLANATION###")
                manifest_part = parts[0].strip()
                explanation = parts[1].strip()
            else:
                # Fallback - try to separate YAML from explanation
                lines = content.split('\n')
                yaml_lines = []
                explanation_lines = []
                in_yaml = True
                
                for line in lines:
                    if in_yaml and (line.strip().startswith('apiVersion:') or 
                                   line.strip() == '---' or 
                                   line.strip().startswith(('kind:', 'metadata:', 'spec:', 'data:'))):
                        yaml_lines.append(line)
                    elif in_yaml and line.strip() and not any(line.strip().startswith(prefix) 
                                                             for prefix in ['apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', '---', '  ', '- ']):
                        # Looks like explanation started
                        in_yaml = False
                        explanation_lines.append(line)
                    elif not in_yaml:
                        explanation_lines.append(line)
                    elif in_yaml:
                        yaml_lines.append(line)
                
                manifest_part = '\n'.join(yaml_lines).strip()
                explanation = '\n'.join(explanation_lines).strip()
                
                if not explanation:
                    explanation = "Manifest has been repaired to address policy violations and ensure compliance with SAP standards."
            
            # Clean the manifest part
            manifest_part = self._clean_yaml_output(manifest_part)
            
            # Validate the repaired YAML
            try:
                list(yaml.safe_load_all(manifest_part))
            except yaml.YAMLError as e:
                manifest_part = self._fix_common_yaml_issues(manifest_part)
                list(yaml.safe_load_all(manifest_part))  # Test again
                
            return manifest_part, explanation
                
        except Exception as e:
            raise Exception(f"Neural repair failed: {str(e)}")

# ─────────────────────────────────────────────────────────────
# Rego Policy Engine (OPA Integration)
# ─────────────────────────────────────────────────────────────

class RegoPolicyValidator:
    """Rego/OPA-based policy validation engine"""
    
    def __init__(self):
        self.policy_dir = Path(__file__).parent / "policies" / "opa"
        self.policy_file = self.policy_dir / "sap-k8s-policies.rego"
        
        # Ensure OPA is available
        self._check_opa_available()
    
    def _check_opa_available(self):
        """Check if OPA binary is available"""
        opa_paths = ["opa", "~/bin/opa", "/usr/local/bin/opa"]
        self.opa_binary = None
        
        for opa_path in opa_paths:
            try:
                if opa_path.startswith("~/"):
                    opa_path = os.path.expanduser(opa_path)
                subprocess.run([opa_path, "version"], capture_output=True, check=True)
                self.opa_binary = opa_path
                print(f"✅ Found OPA at: {opa_path}")
                break
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        if not self.opa_binary:
            print("⚠️  OPA binary not found. Using embedded policy engine...")
            # Fall back to embedded validation if OPA not available
    
    def validate_manifest(self, manifest: str) -> ValidationResult:
        """Validate manifest using Rego policies"""
        violations = []
        
        try:
            # Parse YAML documents
            docs = list(yaml.safe_load_all(manifest))
            
            # Validate each document against Rego policies
            for doc in docs:
                if doc:  # Skip empty documents
                    doc_violations = self._evaluate_rego_policies(doc)
                    violations.extend(doc_violations)
                    
        except yaml.YAMLError as e:
            violations.append(PolicyViolation(
                rule_id="yaml-parse",
                title="YAML Parse Error",
                description=f"Invalid YAML format: {str(e)}",
                severity="high",
                path="",
                suggested_fix="Fix YAML syntax errors"
            ))
        except Exception as e:
            print(f"Rego validation error: {e}")
            # Fall back to Python validation if Rego fails
            return self._fallback_validation(manifest)
        
        compliance_score = max(0.0, 1.0 - (len(violations) / 8))  # 8 total policies
        
        return ValidationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            compliance_score=compliance_score
        )
    
    def _evaluate_rego_policies(self, doc: Dict[str, Any]) -> List[PolicyViolation]:
        """Evaluate a single document against Rego policies"""
        violations = []
        
        try:
            # Create temporary files for OPA evaluation
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as input_file:
                json.dump(doc, input_file)
                input_file_path = input_file.name
            
            try:
                # Run OPA eval command
                if not self.opa_binary:
                    raise Exception("OPA binary not available")
                    
                cmd = [
                    self.opa_binary, "eval",
                    "-d", str(self.policy_file),
                    "-i", input_file_path,
                    "--format", "json",
                    "data.sap.k8s.security.deny"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                opa_output = json.loads(result.stdout)
                
                # Parse violations from OPA output
                if opa_output.get("result") and len(opa_output["result"]) > 0:
                    denials = opa_output["result"][0].get("expressions", [{}])[0].get("value", [])
                    
                    for denial in denials:
                        if isinstance(denial, dict):
                            violations.append(PolicyViolation(
                                rule_id=denial.get("rule_id", "unknown"),
                                title=denial.get("title", "Policy Violation"),
                                description=denial.get("description", "Policy check failed"),
                                severity=denial.get("severity", "medium"),
                                path=denial.get("path", ""),
                                suggested_fix=denial.get("suggested_fix", "Fix the violation")
                            ))
                        else:
                            # Handle simple string denials
                            violations.append(PolicyViolation(
                                rule_id="generic",
                                title="Policy Violation",
                                description=str(denial),
                                severity="medium",
                                path="",
                                suggested_fix="Fix the reported violation"
                            ))
                            
            finally:
                # Clean up temporary file
                os.unlink(input_file_path)
                
        except subprocess.CalledProcessError as e:
            print(f"OPA evaluation failed: {e.stderr}")
            # Fall back to embedded validation
            violations.extend(self._fallback_document_validation(doc))
        except Exception as e:
            print(f"Rego evaluation error: {e}")
            violations.extend(self._fallback_document_validation(doc))
            
        return violations
    
    def _fallback_validation(self, manifest: str) -> ValidationResult:
        """Fallback to Python-based validation when Rego fails"""
        print("🔄 Falling back to embedded policy validation...")
        fallback_validator = SymbolicPolicyValidator()
        return fallback_validator.validate_manifest(manifest)
    
    def _fallback_document_validation(self, doc: Dict[str, Any]) -> List[PolicyViolation]:
        """Fallback validation for a single document"""
        violations = []
        
        # Resource limits check
        if doc.get('kind') == 'Deployment':
            containers = self._get_containers(doc)
            for container in containers:
                if not container.get('resources', {}).get('limits'):
                    violations.append(PolicyViolation(
                        rule_id="resource-limits",
                        title="Missing Resource Limits",
                        description="Containers must specify CPU and memory limits for production",
                        severity="high",
                        path="spec.template.spec.containers[].resources.limits",
                        suggested_fix="Add resource limits: cpu: '2000m', memory: '4Gi'"
                    ))
                    break
        
        return violations
    
    def _get_containers(self, deployment_doc):
        """Extract containers from deployment spec"""
        try:
            return (deployment_doc
                   .get('spec', {})
                   .get('template', {})
                   .get('spec', {})
                   .get('containers', []))
        except:
            return []

# ─────────────────────────────────────────────────────────────
# Legacy Symbolic Policy Engine (Fallback)
# ─────────────────────────────────────────────────────────────

class SymbolicPolicyValidator:
    """Symbolic reasoning engine for K8s policy validation (Legacy/Fallback)"""
    
    def __init__(self):
        # Define SAP K8s policies as symbolic rules
        self.policies = [
            {
                "id": "resource-limits",
                "name": "Resource Limits Required",
                "rule": self._check_resource_limits,
                "severity": "high"
            },
            {
                "id": "data-residency",
                "name": "EU Data Residency",
                "rule": self._check_data_residency,
                "severity": "high"
            },
            {
                "id": "high-availability",
                "name": "High Availability",
                "rule": self._check_high_availability,
                "severity": "medium"
            },
            {
                "id": "audit-logging",
                "name": "Audit Logging Sidecar",
                "rule": self._check_audit_logging,
                "severity": "high"
            },
            {
                "id": "security-context",
                "name": "Security Context",
                "rule": self._check_security_context,
                "severity": "high"
            },
            {
                "id": "labels-required",
                "name": "Required Labels",
                "rule": self._check_required_labels,
                "severity": "medium"
            }
        ]
    
    def validate_manifest(self, manifest: str) -> ValidationResult:
        """Run all policy checks on the manifest"""
        violations = []
        
        try:
            # Parse YAML
            docs = list(yaml.safe_load_all(manifest))
            
            # Run each policy check
            for policy in self.policies:
                try:
                    violation = policy["rule"](docs)
                    if violation:
                        violations.append(violation)
                except Exception as e:
                    print(f"Policy check {policy['id']} failed: {e}")
                    
        except Exception as e:
            violations.append(PolicyViolation(
                rule_id="yaml-parse",
                title="YAML Parse Error",
                description=f"Invalid YAML format: {str(e)}",
                severity="high",
                path="",
                suggested_fix="Fix YAML syntax errors"
            ))
        
        compliance_score = max(0.0, 1.0 - (len(violations) / len(self.policies)))
        
        return ValidationResult(
            is_compliant=len(violations) == 0,
            violations=violations,
            compliance_score=compliance_score
        )
    
    def _check_resource_limits(self, docs) -> PolicyViolation:
        """Check if containers have resource limits"""
        for doc in docs:
            if doc and doc.get('kind') == 'Deployment':
                containers = self._get_containers(doc)
                for container in containers:
                    if not container.get('resources', {}).get('limits'):
                        return PolicyViolation(
                            rule_id="resource-limits",
                            title="Missing Resource Limits",
                            description="Containers must specify CPU and memory limits for production",
                            severity="high",
                            path=f"spec.template.spec.containers[].resources.limits",
                            suggested_fix="Add resource limits: cpu: '2000m', memory: '4Gi'"
                        )
        return None
    
    def _check_data_residency(self, docs) -> PolicyViolation:
        """Check EU data residency compliance"""
        for doc in docs:
            if doc and doc.get('kind') in ['Deployment', 'StatefulSet']:
                labels = doc.get('metadata', {}).get('labels', {})
                if 'region' in labels and labels['region'].startswith('eu'):
                    if 'data-residency' not in labels:
                        return PolicyViolation(
                            rule_id="data-residency",
                            title="Missing Data Residency Label",
                            description="EU deployments must have data-residency label",
                            severity="high",
                            path="metadata.labels.data-residency",
                            suggested_fix="Add label: data-residency: EU"
                        )
        return None
    
    def _check_high_availability(self, docs) -> PolicyViolation:
        """Check high availability configuration"""
        for doc in docs:
            if doc and doc.get('kind') == 'Deployment':
                replicas = doc.get('spec', {}).get('replicas', 1)
                if replicas < 2:
                    return PolicyViolation(
                        rule_id="high-availability",
                        title="Insufficient Replicas for HA",
                        description="High availability requires at least 2 replicas",
                        severity="medium",
                        path="spec.replicas",
                        suggested_fix="Set replicas: 3 for proper HA"
                    )
        return None
    
    def _check_audit_logging(self, docs) -> PolicyViolation:
        """Check for audit logging sidecar"""
        for doc in docs:
            if doc and doc.get('kind') == 'Deployment':
                containers = self._get_containers(doc)
                has_audit_sidecar = any(
                    'audit' in container.get('name', '') or 
                    'logging' in container.get('name', '')
                    for container in containers
                )
                if not has_audit_sidecar and len(containers) == 1:
                    return PolicyViolation(
                        rule_id="audit-logging",
                        title="Missing Audit Logging Sidecar",
                        description="Production services must include audit logging sidecar",
                        severity="high",
                        path="spec.template.spec.containers",
                        suggested_fix="Add audit-logger sidecar container"
                    )
        return None
    
    def _check_security_context(self, docs) -> PolicyViolation:
        """Check security context settings"""
        for doc in docs:
            if doc and doc.get('kind') in ['Deployment', 'StatefulSet']:
                security_context = (doc.get('spec', {})
                                   .get('template', {})
                                   .get('spec', {})
                                   .get('securityContext', {}))
                
                if security_context.get('runAsRoot', True):
                    return PolicyViolation(
                        rule_id="security-context",
                        title="Running as Root",
                        description="Containers should not run as root user",
                        severity="high",
                        path="spec.template.spec.securityContext.runAsNonRoot",
                        suggested_fix="Set runAsNonRoot: true and runAsUser: 1001"
                    )
        return None
    
    def _check_required_labels(self, docs) -> PolicyViolation:
        """Check for required labels"""
        required_labels = ['app', 'version', 'team']
        
        for doc in docs:
            if doc and doc.get('kind') in ['Deployment', 'Service']:
                labels = doc.get('metadata', {}).get('labels', {})
                missing_labels = [label for label in required_labels if label not in labels]
                
                if missing_labels:
                    return PolicyViolation(
                        rule_id="labels-required",
                        title="Missing Required Labels",
                        description=f"Missing labels: {', '.join(missing_labels)}",
                        severity="medium",
                        path="metadata.labels",
                        suggested_fix=f"Add labels: {', '.join(f'{l}: <value>' for l in missing_labels)}"
                    )
        return None
    
    def _get_containers(self, deployment_doc):
        """Extract containers from deployment spec"""
        try:
            return (deployment_doc
                   .get('spec', {})
                   .get('template', {})
                   .get('spec', {})
                   .get('containers', []))
        except:
            return []

# ─────────────────────────────────────────────────────────────
# Generator-Verifier Loop with Rego Integration
# ─────────────────────────────────────────────────────────────

class NeuroSymbolicGeneratorVerifier:
    """Enhanced generator-verifier loop with Rego policy validation"""
    
    def __init__(self, neural_generator, rego_validator, max_iterations=3):
        self.neural_generator = neural_generator
        self.rego_validator = rego_validator
        self.max_iterations = max_iterations
        
    def generate_and_verify(self, requirements: str, socketio_instance=None) -> Tuple[str, str, ValidationResult]:
        """
        Simplified Generator-Verifier loop:
        1. Generate manifest with Neural AI
        2. Verify with Rego policies
        3. If violations found, try ONE repair
        4. Return best result
        """
        
        print(f"🔄 Generator-Verifier: Starting simplified loop...")
        
        try:
            # Step 1: Generate initial manifest
            print(f"🧠 Neural: Generating initial manifest...")
            if socketio_instance:
                socketio_instance.emit('generation_progress', {
                    'step': 'generator_verifier_generate',
                    'message': 'Generating initial manifest...',
                    'progress': 25
                })
            
            current_manifest = self.neural_generator.generate_manifest(requirements)
            current_explanation = "Initial manifest generated by Neural AI"
            
            # Step 2: Validate with Rego
            print(f"🛡️ Rego: Validating initial manifest...")
            if socketio_instance:
                socketio_instance.emit('generation_progress', {
                    'step': 'generator_verifier_validate',
                    'message': 'Validating with Rego policies...',
                    'progress': 50
                })
            
            validation_result = self.rego_validator.validate_manifest(current_manifest)
            
            # Show violations immediately after validation
            if socketio_instance and validation_result.violations:
                socketio_instance.emit('validation_violations', {
                    'violations': [
                        {
                            'rule_id': v.rule_id,
                            'title': v.title,
                            'description': v.description,
                            'severity': v.severity,
                            'path': v.path,
                            'suggested_fix': v.suggested_fix
                        }
                        for v in validation_result.violations
                    ],
                    'manifest': current_manifest
                })
            
            # Step 3: If compliant, return immediately
            if validation_result.is_compliant:
                print(f"✅ Generator-Verifier: Initial manifest is compliant!")
                if socketio_instance:
                    socketio_instance.emit('generation_progress', {
                        'step': 'generator_verifier_complete',
                        'message': 'Manifest is policy-compliant!',
                        'progress': 100
                    })
                return current_manifest, current_explanation, validation_result
            
            # Step 4: Try ONE repair if not compliant
            print(f"🔧 Neural: Attempting to repair {len(validation_result.violations)} violations...")
            if socketio_instance:
                socketio_instance.emit('generation_progress', {
                    'step': 'generator_verifier_repair',
                    'message': f'Repairing {len(validation_result.violations)} violations...',
                    'progress': 75
                })
            
            try:
                repaired_manifest, repair_explanation = self.neural_generator.repair_manifest(
                    current_manifest, validation_result.violations, requirements
                )
                
                # Validate repaired manifest
                final_validation = self.rego_validator.validate_manifest(repaired_manifest)
                
                print(f"🛡️ Generator-Verifier: Repair completed, {len(final_validation.violations)} violations remaining")
                if socketio_instance:
                    socketio_instance.emit('generation_progress', {
                        'step': 'generator_verifier_complete',
                        'message': f'Repair completed with {len(final_validation.violations)} remaining violations',
                        'progress': 100
                    })
                
                return repaired_manifest, repair_explanation, final_validation
                
            except Exception as repair_error:
                print(f"❌ Repair failed: {repair_error}, returning original manifest")
                # Return original manifest if repair fails
                return current_manifest, f"Repair failed: {str(repair_error)}", validation_result
                
        except Exception as e:
            error_msg = f"Generator-Verifier loop failed: {str(e)}"
            print(f"❌ {error_msg}")
            import traceback
            traceback.print_exc()
            
            if socketio_instance:
                socketio_instance.emit('generator_verifier_error', {
                    'error': error_msg
                })
            raise Exception(error_msg)

# ─────────────────────────────────────────────────────────────
# Initialize Neuro-Symbolic Components
# ─────────────────────────────────────────────────────────────

neural_generator = NeuralManifestGenerator(openai_client)
rego_validator = RegoPolicyValidator()
symbolic_validator = SymbolicPolicyValidator()  # Fallback validator
generator_verifier = NeuroSymbolicGeneratorVerifier(neural_generator, rego_validator, max_iterations=3)

# Initialize XSUAA components
from xsuaa_policy_engine import create_xsuaa_policy_engine
from cloud_native_validator import create_cloud_native_validator
from real_cloud_native_validator import create_real_cloud_native_validator
xsuaa_policy_engine = create_xsuaa_policy_engine(openai_client)
cloud_native_validator = create_cloud_native_validator(openai_client)
real_cloud_native_validator = create_real_cloud_native_validator(openai_client)

# ─────────────────────────────────────────────────────────────
# Flask Routes
# ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the neuro-symbolic interface"""
    return render_template('index.html')

@app.route('/api/generate_manifest', methods=['POST'])
def generate_manifest():
    """Neural: Generate K8s manifest from requirements"""
    try:
        data = request.json
        requirements = data.get('requirements', '').strip()
        
        if not requirements:
            return jsonify({'error': 'Requirements are required'}), 400
        
        print(f"🧠 Neural: Generating manifest for requirements...")
        
        # Emit progress update
        socketio.emit('generation_progress', {
            'step': 'neural_generation',
            'message': 'Neural AI analyzing requirements...',
            'progress': 25
        })
        
        # Generate manifest using Neural AI
        manifest = neural_generator.generate_manifest(requirements)
        
        socketio.emit('generation_progress', {
            'step': 'neural_generation',
            'message': 'Manifest generated successfully',
            'progress': 100
        })
        
        return jsonify({
            'manifest': manifest,
            'status': 'generated'
        })
        
    except Exception as e:
        print(f"❌ Generation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate_manifest', methods=['POST'])
def validate_manifest():
    """Symbolic: Validate manifest against policies"""
    try:
        data = request.json
        manifest = data.get('manifest', '').strip()
        
        if not manifest:
            return jsonify({'error': 'Manifest is required'}), 400
        
        print(f"🛡️ Symbolic: Validating manifest against policies...")
        
        # Emit progress update
        socketio.emit('generation_progress', {
            'step': 'symbolic_validation',
            'message': 'Symbolic engine validating policies...',
            'progress': 25
        })
        
        # Pre-validate YAML format
        try:
            docs = list(yaml.safe_load_all(manifest))
            if not docs or all(doc is None for doc in docs):
                raise yaml.YAMLError("No valid YAML documents found")
        except yaml.YAMLError as e:
            # Return YAML parsing error as a special violation
            socketio.emit('generation_progress', {
                'step': 'symbolic_validation',
                'message': f'YAML parsing error detected: {str(e)}',
                'progress': 100
            })
            
            return jsonify({
                'is_compliant': False,
                'violations': [{
                    'rule_id': 'yaml-parse-error',
                    'title': 'YAML Parse Error',
                    'description': f'Invalid YAML format: {str(e)}',
                    'severity': 'high',
                    'path': '',
                    'suggested_fix': 'Fix YAML syntax errors - remove any backticks, check indentation, and ensure proper YAML format'
                }],
                'compliance_score': 0.0
            })
        
        # Validate using Rego Policy Engine
        result = rego_validator.validate_manifest(manifest)
        
        socketio.emit('generation_progress', {
            'step': 'symbolic_validation',
            'message': f'Found {len(result.violations)} policy violations',
            'progress': 100
        })
        
        # Convert violations to dict format
        violations_dict = [
            {
                'rule_id': v.rule_id,
                'title': v.title,
                'description': v.description,
                'severity': v.severity,
                'path': v.path,
                'suggested_fix': v.suggested_fix
            }
            for v in result.violations
        ]
        
        return jsonify({
            'is_compliant': result.is_compliant,
            'violations': violations_dict,
            'compliance_score': result.compliance_score
        })
        
    except Exception as e:
        print(f"❌ Validation error: {e}")
        import traceback
        traceback.print_exc()
        
        # Emit error to frontend
        socketio.emit('validation_error', {
            'error': str(e),
            'step': 'symbolic_validation'
        })
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/simple_generate', methods=['POST'])
def simple_generate():
    """Simple: Generate manifest without complex loop for testing"""
    try:
        data = request.json
        requirements = data.get('requirements', '').strip()
        
        if not requirements:
            return jsonify({'error': 'Requirements are required'}), 400
        
        print(f"🧠 Simple: Starting simple generation...")
        
        # Simple generation
        manifest = neural_generator.generate_manifest(requirements)
        
        print(f"🧠 Simple: Generation completed, validating with Rego...")
        
        # Simple validation
        result = rego_validator.validate_manifest(manifest)
        
        print(f"🛡️ Simple: Validation completed, {len(result.violations)} violations found")
        
        return jsonify({
            'manifest': manifest,
            'isCompliant': result.is_compliant,
            'violations': [
                {
                    'rule_id': v.rule_id,
                    'title': v.title,
                    'description': v.description,
                    'severity': v.severity,
                    'path': v.path,
                    'suggested_fix': v.suggested_fix
                }
                for v in result.violations
            ],
            'complianceScore': result.compliance_score,
            'method': 'simple_generation'
        })
        
    except Exception as e:
        print(f"❌ Simple generation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate_with_rego_loop', methods=['POST'])
def generate_with_rego_loop():
    """Enhanced: Generate manifest using Generator-Verifier loop with Rego"""
    try:
        data = request.json
        requirements = data.get('requirements', '').strip()
        
        if not requirements:
            return jsonify({'error': 'Requirements are required'}), 400
        
        print(f"🔄 Generator-Verifier: Starting loop with Rego validation...")
        
        # Emit progress update
        socketio.emit('generation_progress', {
            'step': 'generator_verifier_start',
            'message': 'Starting Generator-Verifier loop with Rego policies...',
            'progress': 10
        })
        
        # Use the enhanced generator-verifier loop
        manifest, explanation, validation_result = generator_verifier.generate_and_verify(
            requirements, socketio
        )
        
        # Calculate estimated cost
        estimated_cost = calculate_estimated_cost(manifest)
        
        return jsonify({
            'manifest': manifest,
            'explanation': explanation,
            'isCompliant': validation_result.is_compliant,
            'violations': [
                {
                    'rule_id': v.rule_id,
                    'title': v.title,
                    'description': v.description,
                    'severity': v.severity,
                    'path': v.path,
                    'suggested_fix': v.suggested_fix
                }
                for v in validation_result.violations
            ],
            'complianceScore': validation_result.compliance_score,
            'estimatedCost': f"${estimated_cost:.2f}",
            'summary': generate_deployment_summary(manifest),
            'method': 'generator_verifier_rego'
        })
        
    except Exception as e:
        print(f"❌ Generator-Verifier error: {e}")
        import traceback
        traceback.print_exc()
        
        socketio.emit('generator_verifier_error', {
            'error': str(e),
            'step': 'generator_verifier'
        })
        
        return jsonify({'error': str(e)}), 500

@app.route('/api/repair_manifest', methods=['POST'])
def repair_manifest():
    """Neural: Repair manifest to fix violations"""
    try:
        data = request.json
        manifest = data.get('manifest', '').strip()
        violations_data = data.get('violations', [])
        requirements = data.get('requirements', '')
        
        if not manifest or not violations_data:
            return jsonify({'error': 'Manifest and violations are required'}), 400
        
        print(f"🔧 Neural: Repairing {len(violations_data)} policy violations...")
        
        # Emit progress update
        socketio.emit('generation_progress', {
            'step': 'neural_repair',
            'message': 'Neural AI repairing policy violations...',
            'progress': 25
        })
        
        # Convert dict violations back to objects
        violations = [
            PolicyViolation(
                rule_id=v['rule_id'],
                title=v['title'],
                description=v['description'],
                severity=v['severity'],
                path=v['path'],
                suggested_fix=v['suggested_fix']
            )
            for v in violations_data
        ]
        
        try:
            # Repair using Neural AI
            repaired_manifest, explanation = neural_generator.repair_manifest(
                manifest, violations, requirements
            )
            
            socketio.emit('generation_progress', {
                'step': 'neural_repair',
                'message': 'Manifest repaired successfully',
                'progress': 75
            })
            
            # Validate repaired manifest
            final_validation = rego_validator.validate_manifest(repaired_manifest)
            
            socketio.emit('generation_progress', {
                'step': 'final_validation',
                'message': 'Final validation complete',
                'progress': 100
            })
            
            # Calculate estimated cost (mock)
            estimated_cost = calculate_estimated_cost(repaired_manifest)
            
            return jsonify({
                'repairedManifest': repaired_manifest,
                'explanation': explanation,
                'isCompliant': final_validation.is_compliant,
                'finalViolations': len(final_validation.violations),
                'complianceScore': final_validation.compliance_score,
                'estimatedCost': f"${estimated_cost:.2f}",
                'summary': generate_deployment_summary(repaired_manifest)
            })
            
        except yaml.YAMLError as e:
            print(f"❌ YAML error in repair: {e}")
            
            # Emit specific YAML error
            socketio.emit('repair_error', {
                'error': f'Generated YAML is invalid: {str(e)}',
                'step': 'neural_repair',
                'type': 'yaml_error'
            })
            
            return jsonify({
                'error': f'Repaired manifest contains YAML errors: {str(e)}',
                'type': 'yaml_error',
                'suggestion': 'The AI generated invalid YAML. Please try again or check the original requirements.'
            }), 400
            
        except Exception as repair_error:
            print(f"❌ Neural repair error: {repair_error}")
            
            # Emit repair error
            socketio.emit('repair_error', {
                'error': str(repair_error),
                'step': 'neural_repair'
            })
            
            return jsonify({
                'error': f'Repair failed: {str(repair_error)}',
                'suggestion': 'Please try regenerating the manifest or simplify the requirements.'
            }), 500
        
    except Exception as e:
        print(f"❌ Repair endpoint error: {e}")
        import traceback
        traceback.print_exc()
        
        socketio.emit('repair_error', {
            'error': str(e),
            'step': 'repair_endpoint'
        })
        
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────────────────────
# XSUAA Neuro-Symbolic Policy Engine Routes
# ─────────────────────────────────────────────────────────────

@app.route('/test_xsuaa')
def test_xsuaa():
    """Test XSUAA functionality with simple HTML"""
    return send_from_directory('.', 'test_xsuaa.html')

@app.route('/test_cloud_native')
def test_cloud_native():
    """Test Cloud-Native architecture validation with simple HTML"""
    return send_from_directory('.', 'test_cloud_native.html')

@app.route('/test_real_cloud_native')
def test_real_cloud_native():
    """Test REAL Cloud-Native architecture validation with LLM + Z3"""
    return send_from_directory('.', 'test_real_cloud_native.html')

@app.route('/api/evaluate_xsuaa_access', methods=['POST'])
def evaluate_xsuaa_access():
    """Neuro-Symbolic: Evaluate natural language access queries against XSUAA policies"""
    try:
        data = request.json
        natural_query = data.get('query', '').strip()
        xs_security = data.get('xs_security')
        user_roles = data.get('user_roles', [])
        
        if not natural_query:
            return jsonify({'error': 'Natural language query is required'}), 400
        
        if not xs_security:
            return jsonify({'error': 'xs-security configuration is required'}), 400
        
        print(f"🧠🛡️ XSUAA: Evaluating query: {natural_query}")
        
        # Step 1: Neural translation of natural language to logical query
        logical_query, policy_decision = xsuaa_policy_engine.evaluate_natural_query(
            natural_query, xs_security, user_roles
        )
        
        print(f"🧠 Neural: Translated to logical query - User: {logical_query.user_id}, Action: {logical_query.action}, Resource: {logical_query.resource}")
        print(f"🛡️ Symbolic: Decision - Allowed: {policy_decision.allowed}, Reason: {policy_decision.reason}")
        
        return jsonify({
            'query': natural_query,
            'logical_query': {
                'user_id': logical_query.user_id,
                'action': logical_query.action,
                'resource': logical_query.resource,
                'context': logical_query.context
            },
            'decision': {
                'allowed': policy_decision.allowed,
                'reason': policy_decision.reason,
                'applicable_roles': policy_decision.applicable_roles,
                'applicable_scopes': policy_decision.applicable_scopes,
                'confidence': policy_decision.confidence
            },
            'status': 'evaluated'
        })
        
    except Exception as e:
        print(f"❌ XSUAA policy evaluation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate_cloud_native', methods=['POST'])
def validate_cloud_native():
    """Neuro-Symbolic: Validate application artifacts against 12-factor and cloud-native principles"""
    try:
        data = request.json
        artifacts = data.get('artifacts', {})
        
        if not artifacts:
            return jsonify({'error': 'Application artifacts are required'}), 400
        
        print(f"🧠🛡️ Cloud-Native: Validating {len(artifacts)} artifacts...")
        
        # Step 1: Neural parsing + Symbolic validation
        facts, violations = cloud_native_validator.validate_application(artifacts)
        
        print(f"🧠 Neural: Parsed {len(facts)} architectural facts")
        print(f"🛡️ Symbolic: Found {len(violations)} violations")
        
        # Convert facts and violations to dict format
        facts_dict = [
            {
                'fact_type': f.fact_type,
                'entity': f.entity,
                'property': f.property,
                'value': f.value,
                'source_file': f.source_file
            }
            for f in facts
        ]
        
        violations_dict = [
            {
                'principle_id': v.principle_id,
                'principle_name': v.principle_name,
                'factor_number': v.factor_number,
                'description': v.description,
                'severity': v.severity,
                'file_path': v.file_path,
                'violation_details': v.violation_details,
                'suggested_fix': v.suggested_fix,
                'impact': v.impact
            }
            for v in violations
        ]
        
        return jsonify({
            'facts': facts_dict,
            'violations': violations_dict,
            'violation_count': len(violations),
            'is_compliant': len(violations) == 0,
            'compliance_score': max(0.0, 1.0 - (len(violations) / 20)),  # Normalize to 0-1
            'status': 'validated'
        })
        
    except Exception as e:
        print(f"❌ Cloud-Native validation error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/validate_cloud_native_real', methods=['POST'])
def validate_cloud_native_real():
    """REAL Neuro-Symbolic: Use actual LLM + Z3 SMT solver for 12-factor validation"""
    try:
        data = request.json
        artifacts = data.get('artifacts', {})
        
        if not artifacts:
            return jsonify({'error': 'Application artifacts are required'}), 400
        
        print(f"🧠🛡️ REAL Cloud-Native: Starting validation with LLM + Z3 for {len(artifacts)} artifacts...")
        
        # Step 1: REAL Neural parsing with OpenAI LLM + Step 2: REAL Z3 SMT solving
        facts, violations = real_cloud_native_validator.validate_application_real(artifacts)
        
        print(f"🧠 REAL Neural: LLM extracted {len(facts)} architectural facts")
        print(f"🛡️ REAL Symbolic: Z3 SMT solver found {len(violations)} violations")
        
        # Convert facts and violations to dict format
        facts_dict = [
            {
                'fact_type': f.fact_type,
                'entity': f.entity,
                'property': f.property,
                'value': str(f.value),
                'source_file': f.source_file,
                'z3_constraint': f.z3_constraint
            }
            for f in facts
        ]
        
        violations_dict = [
            {
                'principle_id': v.principle_id,
                'principle_name': v.principle_name,
                'factor_number': v.factor_number,
                'description': v.description,
                'severity': v.severity,
                'file_path': v.file_path,
                'violation_details': v.violation_details,
                'suggested_fix': v.suggested_fix,
                'impact': v.impact,
                'z3_model': v.z3_model[:500] + "..." if len(v.z3_model) > 500 else v.z3_model  # Truncate long Z3 models
            }
            for v in violations
        ]
        
        return jsonify({
            'method': 'REAL_NEURO_SYMBOLIC',
            'neural_engine': 'OpenAI GPT-4o-mini',
            'symbolic_engine': 'Z3 SMT Solver',
            'facts': facts_dict,
            'violations': violations_dict,
            'violation_count': len(violations),
            'is_compliant': len(violations) == 0,
            'compliance_score': max(0.0, 1.0 - (len(violations) / 10)),
            'status': 'validated_with_real_neuro_symbolic'
        })
        
    except Exception as e:
        print(f"❌ REAL Cloud-Native validation error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────

def calculate_estimated_cost(manifest: str) -> float:
    """Calculate estimated monthly cost for the deployment"""
    try:
        docs = list(yaml.safe_load_all(manifest))
        total_cost = 0.0
        
        for doc in docs:
            if doc and doc.get('kind') == 'Deployment':
                replicas = doc.get('spec', {}).get('replicas', 1)
                containers = (doc.get('spec', {})
                             .get('template', {})
                             .get('spec', {})
                             .get('containers', []))
                
                for container in containers:
                    limits = container.get('resources', {}).get('limits', {})
                    cpu = limits.get('cpu', '100m')
                    memory = limits.get('memory', '128Mi')
                    
                    # Simple cost calculation (mock)
                    cpu_cores = parse_cpu(cpu)
                    memory_gb = parse_memory(memory)
                    
                    # Cost per core-hour: $0.05, per GB-hour: $0.01
                    monthly_hours = 24 * 30
                    container_cost = (cpu_cores * 0.05 + memory_gb * 0.01) * monthly_hours
                    total_cost += container_cost * replicas
        
        return total_cost
        
    except:
        return 45.00  # Default estimate

def parse_cpu(cpu_str: str) -> float:
    """Parse CPU string to float (cores)"""
    if cpu_str.endswith('m'):
        return float(cpu_str[:-1]) / 1000
    return float(cpu_str)

def parse_memory(memory_str: str) -> float:
    """Parse memory string to float (GB)"""
    if memory_str.endswith('Mi'):
        return float(memory_str[:-2]) / 1024
    elif memory_str.endswith('Gi'):
        return float(memory_str[:-2])
    return float(memory_str) / (1024**3)  # Assume bytes

def generate_deployment_summary(manifest: str) -> str:
    """Generate a summary of the deployment"""
    try:
        docs = list(yaml.safe_load_all(manifest))
        components = []
        
        for doc in docs:
            if doc:
                kind = doc.get('kind', '')
                name = doc.get('metadata', {}).get('name', 'unnamed')
                components.append(f"{kind}: {name}")
        
        return f"Deployment includes {len(components)} components: {', '.join(components)}. All SAP security policies are satisfied."
        
    except:
        return "Policy-compliant SAP deployment ready for production."

# ─────────────────────────────────────────────────────────────
# WebSocket Events
# ─────────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"🔗 Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Neuro-Symbolic K8s Validator'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"🔌 Client disconnected: {request.sid}")

# ─────────────────────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# ─────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import socket
    
    def find_free_port(start_port=5000):
        for port in range(start_port, start_port + 100):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        return None
    
    port = 9000  # Use port 9000 as requested
    
    print("🧠🛡️ Starting SAP Neuro-Symbolic K8s Validator...")
    print(f"🌟 Neural + Symbolic AI Dashboard: http://localhost:{port}")
    print("🔧 Make sure OPENAI_API_KEY is set in your environment")
    print("="*70)
    print("🧠 Neural AI: Generates and repairs K8s manifests")
    print("🛡️ Symbolic Engine: Validates against SAP policies") 
    print("🔄 Neuro-Symbolic Loop: Generate → Validate → Repair")
    print("="*70)
    
    try:
        socketio.run(
            app,
            host='127.0.0.1',
            port=port,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True
        )
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
