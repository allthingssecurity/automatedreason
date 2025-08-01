#!/usr/bin/env python3
"""
Real Neuro-Symbolic 12-Factor App Validator
Uses actual LLM calls for parsing + Z3 SMT solver for constraint satisfaction
"""

import json
import yaml
import re
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from openai import OpenAI
import z3

@dataclass
class ArchitectureViolation:
    """Represents a violation found by Z3 SMT solver"""
    principle_id: str
    principle_name: str
    factor_number: str
    description: str
    severity: str
    file_path: str
    violation_details: str
    suggested_fix: str
    impact: str
    z3_model: str  # Z3 model that shows the violation

@dataclass
class ArchitectureFact:
    """Represents a fact extracted by LLM and encoded in Z3"""
    fact_type: str
    entity: str
    property: str
    value: Any
    source_file: str
    z3_constraint: str  # The Z3 constraint this fact generates

class RealCloudNativeNeuralParser:
    """Real neural component using OpenAI for parsing application artifacts"""
    
    def __init__(self, openai_client):
        self.client = openai_client
    
    def parse_artifacts_with_llm(self, artifacts: Dict[str, str]) -> List[ArchitectureFact]:
        """Use LLM to extract architectural facts from application files"""
        print("🧠 Neural: Starting LLM analysis of application artifacts...")
        
        facts = []
        
        for file_path, content in artifacts.items():
            print(f"🧠 Neural: Analyzing {file_path} with LLM...")
            
            # Make actual LLM call to parse each file
            file_facts = self._llm_parse_file(file_path, content)
            facts.extend(file_facts)
        
        print(f"🧠 Neural: Extracted {len(facts)} facts using LLM")
        return facts
    
    def _llm_parse_file(self, file_path: str, content: str) -> List[ArchitectureFact]:
        """Make actual OpenAI API call to parse a single file"""
        
        system_prompt = """You are an expert cloud-native architecture analyzer. Extract architectural facts from application files that are relevant to 12-factor app principles.

For each fact you find, return a JSON object with:
- fact_type: One of [config_hardcoded, service_dependency, build_secret, filesystem_dependency, admin_process, env_variable]
- entity: The component/module name
- property: The specific property/config name
- value: The actual value found
- description: Brief description of what this means architecturally

Focus on violations of 12-factor principles:
- Factor II: Hardcoded configuration values, secrets in code
- Factor III: Service dependencies not properly declared
- Factor V: Build-time vs runtime separation violations  
- Factor VI: Filesystem dependencies, stateful processes
- Factor XII: Admin processes mixed with app logic

Return JSON array of facts. If no relevant facts found, return empty array []."""

        user_prompt = f"""Analyze this {file_path} file for 12-factor app architectural violations:

File: {file_path}
Content:
```
{content[:2000]}  # Limit content to avoid token limits
```

Extract architectural facts as JSON array."""

        try:
            print(f"🧠 Neural: Making OpenAI API call for {file_path}...")
            
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=1500
            )
            
            response_text = response.choices[0].message.content.strip()
            print(f"🧠 Neural: Got LLM response for {file_path}: {len(response_text)} chars")
            
            # Parse LLM response
            try:
                # Clean up response - remove markdown formatting if present
                if "```json" in response_text:
                    response_text = response_text.split("```json")[1].split("```")[0]
                elif "```" in response_text:
                    response_text = response_text.split("```")[1].split("```")[0]
                
                llm_facts = json.loads(response_text)
                
                # Convert to ArchitectureFact objects
                facts = []
                for fact_data in llm_facts:
                    fact = ArchitectureFact(
                        fact_type=fact_data.get('fact_type', 'unknown'),
                        entity=fact_data.get('entity', file_path),
                        property=fact_data.get('property', ''),
                        value=fact_data.get('value', ''),
                        source_file=file_path,
                        z3_constraint=""  # Will be filled by Z3 encoder
                    )
                    facts.append(fact)
                
                print(f"🧠 Neural: Parsed {len(facts)} facts from LLM response")
                return facts
                
            except json.JSONDecodeError as e:
                print(f"🧠 Neural: Failed to parse LLM JSON response: {e}")
                print(f"🧠 Neural: Raw response: {response_text}")
                return []
                
        except Exception as e:
            print(f"🧠 Neural: LLM API call failed: {e}")
            return []

class RealCloudNativeZ3Validator:
    """Real symbolic engine using Z3 SMT solver for constraint satisfaction"""
    
    def __init__(self):
        print("🛡️ Symbolic: Initializing Z3 SMT solver...")
        self.solver = z3.Solver()
        self.variables = {}  # Track Z3 variables
        self.constraints = []  # Track Z3 constraints
    
    def validate_with_z3(self, facts: List[ArchitectureFact]) -> List[ArchitectureViolation]:
        """Use Z3 SMT solver to find 12-factor violations"""
        print("🛡️ Symbolic: Starting Z3 constraint solving...")
        
        # Reset solver for fresh analysis
        self.solver = z3.Solver()
        self.variables = {}
        self.constraints = []
        
        # Step 1: Encode facts as Z3 constraints
        self._encode_facts_to_z3(facts)
        
        # Step 2: Add 12-factor principle constraints
        self._add_12factor_constraints()
        
        # Step 3: Solve for violations
        violations = self._solve_for_violations()
        
        print(f"🛡️ Symbolic: Z3 found {len(violations)} violations")
        return violations
    
    def _encode_facts_to_z3(self, facts: List[ArchitectureFact]):
        """Encode architectural facts as Z3 boolean variables and constraints"""
        print("🛡️ Symbolic: Encoding facts as Z3 constraints...")
        
        for i, fact in enumerate(facts):
            # Create Z3 boolean variable for each fact
            var_name = f"fact_{fact.fact_type}_{i}"
            z3_var = z3.Bool(var_name)
            self.variables[var_name] = {
                'z3_var': z3_var,
                'fact': fact
            }
            
            # Fact exists (always true since we found it)
            self.solver.add(z3_var == True)
            
            # Store Z3 constraint in fact for reference
            fact.z3_constraint = f"{var_name} == True"
            
            print(f"🛡️ Symbolic: Encoded fact {fact.fact_type} as {var_name}")
    
    def _add_12factor_constraints(self):
        """Add 12-factor principle constraints to Z3 solver"""
        print("🛡️ Symbolic: Adding 12-factor principle constraints to Z3...")
        
        # Factor II: Configuration stored in environment
        # Constraint: If config_hardcoded exists, then violates_factor_ii
        config_hardcoded_vars = [
            var_data['z3_var'] for var_name, var_data in self.variables.items()
            if 'fact' in var_data and var_data['fact'].fact_type == 'config_hardcoded'
        ]
        
        if config_hardcoded_vars:
            violates_factor_ii = z3.Bool("violates_factor_ii")
            self.variables['violates_factor_ii'] = {
                'z3_var': violates_factor_ii,
                'principle': 'Factor II: Config'
            }
            # If any config is hardcoded, then factor II is violated
            self.solver.add(violates_factor_ii == z3.Or(config_hardcoded_vars))
            print(f"🛡️ Symbolic: Added Factor II constraint with {len(config_hardcoded_vars)} config violations")
        else:
            print("🛡️ Symbolic: No config_hardcoded facts found for Factor II")
        
        # Factor V: Build, release, run separation
        # Constraint: If build_secret exists, then violates_factor_v
        build_secret_vars = [
            var_data['z3_var'] for var_name, var_data in self.variables.items()
            if 'fact' in var_data and var_data['fact'].fact_type == 'build_secret'
        ]
        
        if build_secret_vars:
            violates_factor_v = z3.Bool("violates_factor_v")
            self.variables['violates_factor_v'] = {
                'z3_var': violates_factor_v,
                'principle': 'Factor V: Build/Release/Run'
            }
            self.solver.add(violates_factor_v == z3.Or(build_secret_vars))
            print("🛡️ Symbolic: Added Factor V constraint (build secrets)")
        
        # Factor VI: Stateless processes
        # Constraint: If filesystem_dependency exists, then violates_factor_vi
        filesystem_vars = [
            var_data['z3_var'] for var_name, var_data in self.variables.items()
            if 'fact' in var_data and var_data['fact'].fact_type == 'filesystem_dependency'
        ]
        
        if filesystem_vars:
            violates_factor_vi = z3.Bool("violates_factor_vi")
            self.variables['violates_factor_vi'] = {
                'z3_var': violates_factor_vi,
                'principle': 'Factor VI: Stateless Processes'
            }
            self.solver.add(violates_factor_vi == z3.Or(filesystem_vars))
            print("🛡️ Symbolic: Added Factor VI constraint (filesystem dependencies)")
        
        # Factor XII: Admin processes
        # Constraint: If admin_process mixed with app, then violates_factor_xii
        admin_process_vars = [
            var_data['z3_var'] for var_name, var_data in self.variables.items()
            if 'fact' in var_data and var_data['fact'].fact_type == 'admin_process'
        ]
        
        if admin_process_vars:
            violates_factor_xii = z3.Bool("violates_factor_xii")
            self.variables['violates_factor_xii'] = {
                'z3_var': violates_factor_xii,
                'principle': 'Factor XII: Admin Processes'
            }
            self.solver.add(violates_factor_xii == z3.Or(admin_process_vars))
            print("🛡️ Symbolic: Added Factor XII constraint (admin processes)")
    
    def _solve_for_violations(self) -> List[ArchitectureViolation]:
        """Use Z3 to solve for violations and generate explanations"""
        print("🛡️ Symbolic: Running Z3 solver to find violations...")
        
        violations = []
        
        # Check if the constraints are satisfiable
        result = self.solver.check()
        print(f"🛡️ Symbolic: Z3 solver result: {result}")
        
        if result == z3.sat:
            model = self.solver.model()
            print("🛡️ Symbolic: Z3 found a satisfying model, analyzing violations...")
            
            # Check each violation variable
            violation_vars = [
                (var_name, var_data) for var_name, var_data in self.variables.items()
                if var_name.startswith('violates_')
            ]
            
            for var_name, var_data in violation_vars:
                z3_var = var_data['z3_var']
                model_value = model[z3_var] if z3_var in model else "undefined"
                print(f"🛡️ Symbolic: Checking {var_name} = {model_value}")
                
                # Check if this violation is true in the model
                if z3.is_true(model[z3_var]):
                    print(f"🛡️ Symbolic: Z3 detected violation: {var_name}")
                    
                    # Find the contributing facts
                    contributing_facts = self._find_contributing_facts(var_name, model)
                    
                    # Create violation object
                    violation = self._create_violation_from_z3(var_name, var_data, contributing_facts, model)
                    violations.append(violation)
                else:
                    print(f"🛡️ Symbolic: No violation for {var_name} (value: {model_value})")
        
        elif result == z3.unsat:
            print("🛡️ Symbolic: Z3 constraints are unsatisfiable - no violations found")
        else:
            print("🛡️ Symbolic: Z3 solver result is unknown")
        
        return violations
    
    def _find_contributing_facts(self, violation_var: str, model: z3.ModelRef) -> List[ArchitectureFact]:
        """Find the facts that contribute to a violation"""
        contributing_facts = []
        
        # Map violation variables to their contributing fact types
        fact_type_mapping = {
            'violates_factor_ii': 'config_hardcoded',
            'violates_factor_v': 'build_secret', 
            'violates_factor_vi': 'filesystem_dependency',
            'violates_factor_xii': 'admin_process'
        }
        
        target_fact_type = fact_type_mapping.get(violation_var)
        if target_fact_type:
            for var_name, var_data in self.variables.items():
                if var_data.get('fact') and var_data['fact'].fact_type == target_fact_type:
                    if z3.is_true(model[var_data['z3_var']]):
                        contributing_facts.append(var_data['fact'])
        
        return contributing_facts
    
    def _create_violation_from_z3(self, var_name: str, var_data: Dict, contributing_facts: List[ArchitectureFact], model: z3.ModelRef) -> ArchitectureViolation:
        """Create violation object from Z3 solver results"""
        
        principle_mapping = {
            'violates_factor_ii': {
                'id': 'config',
                'name': 'Store config in the environment',
                'factor': 'II',
                'severity': 'critical'
            },
            'violates_factor_v': {
                'id': 'build_release_run',
                'name': 'Strictly separate build, release, run',
                'factor': 'V', 
                'severity': 'critical'
            },
            'violates_factor_vi': {
                'id': 'processes',
                'name': 'Execute as stateless processes',
                'factor': 'VI',
                'severity': 'high'
            },
            'violates_factor_xii': {
                'id': 'admin_processes',
                'name': 'Run admin tasks as one-off processes', 
                'factor': 'XII',
                'severity': 'medium'
            }
        }
        
        principle_info = principle_mapping.get(var_name, {})
        
        # Combine information from contributing facts
        file_paths = [fact.source_file for fact in contributing_facts]
        violation_details = f"Z3 detected {len(contributing_facts)} violations: " + \
                          ", ".join([f"{fact.property}={fact.value}" for fact in contributing_facts[:3]])
        
        return ArchitectureViolation(
            principle_id=principle_info.get('id', var_name),
            principle_name=principle_info.get('name', 'Unknown principle'),
            factor_number=principle_info.get('factor', '?'),
            description=f"Z3 SMT solver detected violation of {principle_info.get('name')}",
            severity=principle_info.get('severity', 'medium'),
            file_path=file_paths[0] if file_paths else 'unknown',
            violation_details=violation_details,
            suggested_fix=self._get_fix_suggestion(principle_info.get('id')),
            impact=self._get_impact_description(principle_info.get('id')),
            z3_model=str(model)
        )
    
    def _get_fix_suggestion(self, principle_id: str) -> str:
        """Get fix suggestion based on principle"""
        suggestions = {
            'config': 'Move all configuration to environment variables or BTP service bindings',
            'build_release_run': 'Remove secrets from build artifacts, use runtime environment variables',
            'processes': 'Remove filesystem dependencies, use external storage services',
            'admin_processes': 'Move admin logic to separate scripts or background jobs'
        }
        return suggestions.get(principle_id, 'Review and fix the architectural violation')
    
    def _get_impact_description(self, principle_id: str) -> str:
        """Get impact description based on principle"""
        impacts = {
            'config': 'Makes application non-portable and exposes secrets',
            'build_release_run': 'Violates security and deployment best practices', 
            'processes': 'Prevents horizontal scaling and creates state dependencies',
            'admin_processes': 'Makes application lifecycle management complex'
        }
        return impacts.get(principle_id, 'Violates cloud-native architecture principles')

class RealCloudNativeValidator:
    """Real neuro-symbolic engine combining LLM parsing with Z3 SMT solving"""
    
    def __init__(self, openai_client):
        print("🧠🛡️ Initializing Real Neuro-Symbolic Cloud-Native Validator...")
        self.neural_parser = RealCloudNativeNeuralParser(openai_client)
        self.z3_validator = RealCloudNativeZ3Validator()
        print("🧠🛡️ Real Neuro-Symbolic validator ready!")
    
    def validate_application_real(self, artifacts: Dict[str, str]) -> Tuple[List[ArchitectureFact], List[ArchitectureViolation]]:
        """Real neuro-symbolic validation: LLM parsing → Z3 SMT solving"""
        print("🧠🛡️ Starting REAL neuro-symbolic validation...")
        
        # Step 1: Neural parsing with actual LLM calls
        print("🧠 Step 1: Neural parsing with OpenAI LLM...")
        facts = self.neural_parser.parse_artifacts_with_llm(artifacts)
        
        # Step 2: Symbolic validation with actual Z3 SMT solver
        print("🛡️ Step 2: Symbolic validation with Z3 SMT solver...")
        violations = self.z3_validator.validate_with_z3(facts)
        
        print(f"🧠🛡️ Real neuro-symbolic validation complete: {len(facts)} facts, {len(violations)} violations")
        return facts, violations

# Convenience function for main app
def create_real_cloud_native_validator(openai_client):
    """Create real cloud-native architecture validator with LLM + Z3"""
    return RealCloudNativeValidator(openai_client)