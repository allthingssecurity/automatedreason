#!/usr/bin/env python3
"""
12-Factor App + Cloud-Native Architecture Validator
Neuro-Symbolic reasoning for validating application architecture against best practices
"""

import json
import yaml
import re
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from openai import OpenAI

@dataclass
class ArchitectureViolation:
    """Represents a violation of architectural principles"""
    principle_id: str
    principle_name: str
    factor_number: str  # e.g., "I", "II", "XII" for 12-factor
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    file_path: str
    violation_details: str
    suggested_fix: str
    impact: str

@dataclass
class ArchitectureFact:
    """Represents a parsed fact about the application architecture"""
    fact_type: str  # 'service_dependency', 'config_hardcoded', 'build_artifact', etc.
    entity: str
    property: str
    value: Any
    source_file: str

class CloudNativeNeuralParser:
    """Neural component that parses application artifacts into symbolic facts"""
    
    def __init__(self, openai_client):
        self.client = openai_client
    
    def parse_application_artifacts(self, artifacts: Dict[str, str]) -> List[ArchitectureFact]:
        """Parse application files into architectural facts"""
        facts = []
        
        for file_path, content in artifacts.items():
            if file_path.endswith('mta.yaml') or file_path.endswith('mta.yml'):
                facts.extend(self._parse_mta_yaml(file_path, content))
            elif file_path.endswith('manifest.yml'):
                facts.extend(self._parse_manifest_yml(file_path, content))
            elif file_path.endswith('Dockerfile'):
                facts.extend(self._parse_dockerfile(file_path, content))
            elif file_path.endswith('.env'):
                facts.extend(self._parse_env_file(file_path, content))
            elif file_path.endswith('xs-app.json'):
                facts.extend(self._parse_xs_app_json(file_path, content))
            elif file_path.endswith('.js') or file_path.endswith('.ts'):
                facts.extend(self._parse_code_file(file_path, content))
            elif file_path.endswith('.cds'):
                facts.extend(self._parse_cds_file(file_path, content))
        
        return facts
    
    def _parse_mta_yaml(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse MTA YAML for service dependencies and configuration"""
        facts = []
        try:
            mta = yaml.safe_load(content)
            
            # Extract modules and their dependencies
            for module in mta.get('modules', []):
                module_name = module.get('name')
                
                # Service dependencies
                for req in module.get('requires', []):
                    facts.append(ArchitectureFact(
                        fact_type='service_dependency',
                        entity=module_name,
                        property='requires',
                        value=req.get('name'),
                        source_file=file_path
                    ))
                
                # Check for hardcoded configurations
                env_vars = module.get('properties', {})
                for key, value in env_vars.items():
                    if isinstance(value, str) and any(secret in key.lower() for secret in ['password', 'key', 'secret', 'token']):
                        facts.append(ArchitectureFact(
                            fact_type='config_hardcoded',
                            entity=module_name,
                            property=key,
                            value=value,
                            source_file=file_path
                        ))
            
            # Extract services
            for service in mta.get('resources', []):
                service_name = service.get('name')
                service_type = service.get('type')
                
                facts.append(ArchitectureFact(
                    fact_type='backing_service',
                    entity=service_name,
                    property='type',
                    value=service_type,
                    source_file=file_path
                ))
                
        except Exception as e:
            print(f"Error parsing MTA YAML: {e}")
        
        return facts
    
    def _parse_dockerfile(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse Dockerfile for build/runtime separation violations"""
        facts = []
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines):
            line = line.strip()
            
            # Check for hardcoded secrets in ENV commands
            if line.startswith('ENV '):
                env_part = line[4:].strip()
                if '=' in env_part:
                    key, value = env_part.split('=', 1)
                    if any(secret in key.lower() for secret in ['password', 'key', 'secret', 'token', 'api']):
                        facts.append(ArchitectureFact(
                            fact_type='build_time_secret',
                            entity='dockerfile',
                            property=key,
                            value=value,
                            source_file=f"{file_path}:{line_num+1}"
                        ))
            
            # Check for filesystem writes
            if any(cmd in line.upper() for cmd in ['VOLUME', 'RUN mkdir', 'RUN touch']):
                facts.append(ArchitectureFact(
                    fact_type='filesystem_dependency',
                    entity='dockerfile',
                    property='command',
                    value=line,
                    source_file=f"{file_path}:{line_num+1}"
                ))
        
        return facts
    
    def _parse_env_file(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse .env file for configuration violations"""
        facts = []
        
        lines = content.split('\n')
        for line_num, line in enumerate(lines):
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                facts.append(ArchitectureFact(
                    fact_type='env_file_config',
                    entity='env_file',
                    property=key,
                    value=value,
                    source_file=f"{file_path}:{line_num+1}"
                ))
        
        return facts
    
    def _parse_code_file(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse code files for hardcoded configurations and admin processes"""
        facts = []
        
        # Check for hardcoded configurations
        config_patterns = [
            r'(?:password|secret|key|token)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:localhost|127\.0\.0\.1|192\.168\.\d+\.\d+)',
            r'process\.exit\s*\(',  # Admin processes mixed with app logic
        ]
        
        for pattern in config_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                facts.append(ArchitectureFact(
                    fact_type='code_hardcoded_config',
                    entity=file_path,
                    property='hardcoded_value',
                    value=match.group(0),
                    source_file=f"{file_path}:{line_num}"
                ))
        
        return facts
    
    def _parse_xs_app_json(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse xs-app.json for routing configuration"""
        facts = []
        try:
            xs_app = json.loads(content)
            
            routes = xs_app.get('routes', [])
            for route in routes:
                facts.append(ArchitectureFact(
                    fact_type='app_route',
                    entity='xs_app',
                    property='route',
                    value=route,
                    source_file=file_path
                ))
                
        except Exception as e:
            print(f"Error parsing xs-app.json: {e}")
        
        return facts
    
    def _parse_cds_file(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Parse CDS files for data model dependencies"""
        facts = []
        
        # Simple parsing for service definitions
        service_matches = re.finditer(r'service\s+(\w+)', content)
        for match in service_matches:
            service_name = match.group(1)
            facts.append(ArchitectureFact(
                fact_type='cds_service',
                entity=service_name,
                property='defined',
                value=True,
                source_file=file_path
            ))
        
        return facts

class CloudNativeSymbolicValidator:
    """Symbolic engine that validates architectural facts against 12-factor principles"""
    
    def __init__(self):
        self.rules = [
            {
                "id": "codebase",
                "factor": "I",
                "name": "One codebase tracked in revision control, many deploys",
                "validator": self._validate_codebase,
                "severity": "high"
            },
            {
                "id": "config",
                "factor": "II", 
                "name": "Store config in the environment",
                "validator": self._validate_config,
                "severity": "critical"
            },
            {
                "id": "backing_services",
                "factor": "III",
                "name": "Treat backing services as attached resources", 
                "validator": self._validate_backing_services,
                "severity": "high"
            },
            {
                "id": "build_release_run",
                "factor": "V",
                "name": "Strictly separate build, release, run",
                "validator": self._validate_build_release_run,
                "severity": "critical"
            },
            {
                "id": "processes",
                "factor": "VI",
                "name": "Execute as one or more stateless processes",
                "validator": self._validate_stateless_processes,
                "severity": "high"
            },
            {
                "id": "admin_processes", 
                "factor": "XII",
                "name": "Run admin/management tasks as one-off processes",
                "validator": self._validate_admin_processes,
                "severity": "medium"
            },
            # Cloud-Native specific rules
            {
                "id": "observability",
                "factor": "CN-1",
                "name": "Applications must be observable",
                "validator": self._validate_observability,
                "severity": "medium"
            },
            {
                "id": "immutable_infrastructure",
                "factor": "CN-2", 
                "name": "Infrastructure should be immutable",
                "validator": self._validate_immutable_infra,
                "severity": "high"
            }
        ]
    
    def validate_architecture(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate architecture facts against all rules"""
        violations = []
        
        for rule in self.rules:
            try:
                rule_violations = rule["validator"](facts)
                violations.extend(rule_violations)
            except Exception as e:
                print(f"Rule {rule['id']} validation failed: {e}")
        
        return violations
    
    def _validate_config(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor II: Config stored in environment"""
        violations = []
        
        # Check for hardcoded configurations
        for fact in facts:
            if fact.fact_type in ['config_hardcoded', 'build_time_secret', 'code_hardcoded_config']:
                violations.append(ArchitectureViolation(
                    principle_id="config",
                    principle_name="Store config in the environment",
                    factor_number="II",
                    description=f"Configuration hardcoded in {fact.source_file}",
                    severity="critical",
                    file_path=fact.source_file,
                    violation_details=f"Property '{fact.property}' with value '{fact.value}' is hardcoded",
                    suggested_fix="Move configuration to environment variables or BTP service bindings",
                    impact="Makes application non-portable and exposes secrets in code"
                ))
        
        # Check for .env files in version control
        env_facts = [f for f in facts if f.fact_type == 'env_file_config']
        if env_facts:
            violations.append(ArchitectureViolation(
                principle_id="config",
                principle_name="Store config in the environment", 
                factor_number="II",
                description="Environment file (.env) should not be in version control",
                severity="high",
                file_path=env_facts[0].source_file,
                violation_details="Contains environment-specific configuration",
                suggested_fix="Add .env to .gitignore and use BTP environment variables instead",
                impact="Environment-specific config in VCS violates 12-factor principles"
            ))
        
        return violations
    
    def _validate_backing_services(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor III: Backing services as attached resources"""
        violations = []
        
        # Check if services are properly declared in MTA
        service_deps = [f for f in facts if f.fact_type == 'service_dependency']
        backing_services = [f for f in facts if f.fact_type == 'backing_service']
        
        # Find dependencies that don't have backing service definitions
        declared_services = {s.entity for s in backing_services}
        required_services = {s.value for s in service_deps}
        
        missing_services = required_services - declared_services
        for service in missing_services:
            violations.append(ArchitectureViolation(
                principle_id="backing_services",
                principle_name="Treat backing services as attached resources",
                factor_number="III", 
                description=f"Service '{service}' is required but not properly declared",
                severity="high",
                file_path="mta.yaml",
                violation_details=f"Module requires '{service}' but it's not defined in resources section",
                suggested_fix=f"Add '{service}' to the resources section of mta.yaml",
                impact="Service dependencies are not explicitly managed"
            ))
        
        return violations
    
    def _validate_build_release_run(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor V: Build, release, run separation"""
        violations = []
        
        # Check for build-time secrets
        for fact in facts:
            if fact.fact_type == 'build_time_secret':
                violations.append(ArchitectureViolation(
                    principle_id="build_release_run",
                    principle_name="Strictly separate build, release, run",
                    factor_number="V",
                    description="Secret baked into build artifact",
                    severity="critical", 
                    file_path=fact.source_file,
                    violation_details=f"Environment variable '{fact.property}' contains secret in Dockerfile",
                    suggested_fix="Use runtime environment variables or BTP service bindings instead",
                    impact="Secrets in build artifacts violate security and portability"
                ))
        
        return violations
    
    def _validate_stateless_processes(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor VI: Stateless processes"""
        violations = []
        
        # Check for filesystem dependencies
        for fact in facts:
            if fact.fact_type == 'filesystem_dependency':
                violations.append(ArchitectureViolation(
                    principle_id="processes",
                    principle_name="Execute as one or more stateless processes",
                    factor_number="VI",
                    description="Process depends on local filesystem",
                    severity="high",
                    file_path=fact.source_file,
                    violation_details=f"Command '{fact.value}' creates filesystem dependency",
                    suggested_fix="Use external storage services or keep processes stateless",
                    impact="Prevents horizontal scaling and makes processes non-portable"
                ))
        
        return violations
    
    def _validate_codebase(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor I: One codebase"""
        # For now, assume this is satisfied if we have one MTA
        return []
    
    def _validate_admin_processes(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Factor XII: Admin processes"""
        violations = []
        
        # Check for admin processes mixed with app logic
        for fact in facts:
            if fact.fact_type == 'code_hardcoded_config' and 'process.exit' in str(fact.value):
                violations.append(ArchitectureViolation(
                    principle_id="admin_processes",
                    principle_name="Run admin/management tasks as one-off processes",
                    factor_number="XII",
                    description="Admin logic mixed with application code",
                    severity="medium",
                    file_path=fact.source_file,
                    violation_details="Application contains process.exit() calls",
                    suggested_fix="Move admin tasks to separate scripts or jobs",
                    impact="Makes application lifecycle management complex"
                ))
        
        return violations
    
    def _validate_observability(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Cloud-Native: Observability"""
        # Simplified check - would need more sophisticated analysis
        return []
    
    def _validate_immutable_infra(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Validate Cloud-Native: Immutable infrastructure"""
        violations = []
        
        # Check for volume mounts that suggest mutable infrastructure
        for fact in facts:
            if fact.fact_type == 'filesystem_dependency' and 'VOLUME' in str(fact.value):
                violations.append(ArchitectureViolation(
                    principle_id="immutable_infrastructure",
                    principle_name="Infrastructure should be immutable",
                    factor_number="CN-2",
                    description="Infrastructure uses mutable volumes",
                    severity="medium",
                    file_path=fact.source_file,
                    violation_details=f"Dockerfile contains: {fact.value}",
                    suggested_fix="Use external storage services instead of local volumes",
                    impact="Makes infrastructure mutable and harder to manage"
                ))
        
        return violations

class CloudNativeArchitectValidator:
    """Main engine that combines neural parsing with symbolic validation"""
    
    def __init__(self, openai_client):
        self.parser = CloudNativeNeuralParser(openai_client)
        self.validator = CloudNativeSymbolicValidator()
    
    def validate_application(self, artifacts: Dict[str, str]) -> Tuple[List[ArchitectureFact], List[ArchitectureViolation]]:
        """Main entry point: artifacts → facts → violations"""
        
        # Step 1: Neural parsing
        facts = self.parser.parse_application_artifacts(artifacts)
        
        # Step 2: Symbolic validation  
        violations = self.validator.validate_architecture(facts)
        
        return facts, violations

# Convenience function for main app
def create_cloud_native_validator(openai_client):
    """Create cloud-native architecture validator instance"""
    return CloudNativeArchitectValidator(openai_client)