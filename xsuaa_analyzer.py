#!/usr/bin/env python3
"""
XSUAA Static Security Policy Analyzer
Neuro-Symbolic reasoning for SAP XSUAA access policies
"""

import json
import yaml
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from openai import OpenAI

@dataclass
class XSUAAViolation:
    """Represents an XSUAA security policy violation"""
    rule_id: str
    title: str
    description: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    path: str
    suggested_fix: str
    impact: str  # Who/what is affected

@dataclass
class AccessQuery:
    """Represents a natural language access query"""
    query: str
    query_type: str  # 'access_check', 'role_analysis', 'scope_analysis', 'compliance_check'
    answer: str
    confidence: float

class XSUAASymbolicAnalyzer:
    """Symbolic reasoning engine for XSUAA policies"""
    
    def __init__(self):
        self.policies = [
            {
                "id": "overprivileged-roles",
                "name": "Over-privileged Roles",
                "rule": self._check_overprivileged_roles,
                "severity": "high"
            },
            {
                "id": "unused-scopes",
                "name": "Unused Scopes",
                "rule": self._check_unused_scopes,
                "severity": "medium"
            },
            {
                "id": "weak-authorities",
                "name": "Weak Authority Definitions",
                "rule": self._check_weak_authorities,
                "severity": "high"
            },
            {
                "id": "missing-oauth-config",
                "name": "Missing OAuth Configuration",
                "rule": self._check_oauth_config,
                "severity": "medium"
            },
            {
                "id": "role-segregation",
                "name": "Role Segregation Violations",
                "rule": self._check_role_segregation,
                "severity": "critical"
            }
        ]
    
    def analyze_xsuaa_config(self, xs_security: Dict, mta_config: Dict = None) -> List[XSUAAViolation]:
        """Analyze XSUAA configuration for security violations"""
        violations = []
        
        for policy in self.policies:
            try:
                violation = policy["rule"](xs_security, mta_config)
                if violation:
                    violations.append(violation)
            except Exception as e:
                print(f"Policy check {policy['id']} failed: {e}")
        
        return violations
    
    def _check_overprivileged_roles(self, xs_security: Dict, mta_config: Dict) -> Optional[XSUAAViolation]:
        """Check for roles with excessive privileges"""
        role_templates = xs_security.get('role-templates', [])
        
        for role in role_templates:
            scopes = role.get('scope-references', [])
            if len(scopes) > 10:  # Threshold for too many scopes
                return XSUAAViolation(
                    rule_id="overprivileged-roles",
                    title="Over-privileged Role Detected",
                    description=f"Role '{role.get('name')}' has {len(scopes)} scopes, which may be excessive",
                    severity="high",
                    path=f"role-templates[{role.get('name')}]",
                    suggested_fix="Split role into more specific, focused roles with fewer scopes",
                    impact="Users with this role have broader access than necessary"
                )
        return None
    
    def _check_unused_scopes(self, xs_security: Dict, mta_config: Dict) -> Optional[XSUAAViolation]:
        """Check for scopes not referenced by any role"""
        scopes = {scope['name'] for scope in xs_security.get('scopes', [])}
        referenced_scopes = set()
        
        for role in xs_security.get('role-templates', []):
            referenced_scopes.update(role.get('scope-references', []))
        
        unused = scopes - referenced_scopes
        if unused:
            return XSUAAViolation(
                rule_id="unused-scopes",
                title="Unused Scopes Detected",
                description=f"Scopes not referenced by any role: {', '.join(unused)}",
                severity="medium",
                path="scopes",
                suggested_fix="Remove unused scopes or assign them to appropriate roles",
                impact="Unused scopes create maintenance overhead and potential security risks"
            )
        return None
    
    def _check_weak_authorities(self, xs_security: Dict, mta_config: Dict) -> Optional[XSUAAViolation]:
        """Check for weak authority configurations"""
        for scope in xs_security.get('scopes', []):
            authorities = scope.get('grant-as-authority-to-apps', [])
            if '$XSAPPNAME' in authorities:
                return XSUAAViolation(
                    rule_id="weak-authorities",
                    title="Weak Authority Grant",
                    description=f"Scope '{scope.get('name')}' grants authority to '$XSAPPNAME', which may be too broad",
                    severity="high",
                    path=f"scopes[{scope.get('name')}].grant-as-authority-to-apps",
                    suggested_fix="Specify explicit app names instead of using $XSAPPNAME",
                    impact="Potentially allows unintended applications to access this scope"
                )
        return None
    
    def _check_oauth_config(self, xs_security: Dict, mta_config: Dict) -> Optional[XSUAAViolation]:
        """Check OAuth2 configuration"""
        oauth_config = xs_security.get('oauth2-configuration', {})
        
        if not oauth_config.get('redirect-uris'):
            return XSUAAViolation(
                rule_id="missing-oauth-config",
                title="Missing OAuth Redirect URIs",
                description="No redirect URIs configured for OAuth2",
                severity="medium",
                path="oauth2-configuration.redirect-uris",
                suggested_fix="Add appropriate redirect URIs for your application",
                impact="OAuth2 authentication may fail without proper redirect configuration"
            )
        return None
    
    def _check_role_segregation(self, xs_security: Dict, mta_config: Dict) -> Optional[XSUAAViolation]:
        """Check for segregation of duties violations"""
        # Define conflicting scope patterns
        conflicts = [
            (['approve', 'payment'], 'financial approval and payment'),
            (['create', 'delete', 'admin'], 'creation, deletion, and administration'),
            (['read', 'write', 'execute'], 'read, write, and execute on sensitive data')
        ]
        
        for role in xs_security.get('role-templates', []):
            scopes = [s.lower() for s in role.get('scope-references', [])]
            
            for conflict_patterns, description in conflicts:
                if all(any(pattern in scope for scope in scopes) for pattern in conflict_patterns):
                    return XSUAAViolation(
                        rule_id="role-segregation",
                        title="Segregation of Duties Violation",
                        description=f"Role '{role.get('name')}' combines {description} privileges",
                        severity="critical",
                        path=f"role-templates[{role.get('name')}]",
                        suggested_fix="Split conflicting privileges into separate roles",
                        impact="Violates segregation of duties principles, increasing fraud risk"
                    )
        return None

class XSUAANeuralAnalyzer:
    """Neural component for XSUAA policy analysis and Q&A"""
    
    def __init__(self, openai_client):
        self.client = openai_client
    
    def answer_access_query(self, query: str, xs_security: Dict, violations: List[XSUAAViolation]) -> AccessQuery:
        """Answer natural language queries about XSUAA access policies"""
        
        system_prompt = """You are an expert SAP XSUAA security analyst. Answer questions about access policies, roles, and security compliance based on the provided XSUAA configuration and any detected violations.

Be precise and specific in your answers. If asking about access, determine if it's possible based on the role-templates and scopes defined."""
        
        context = f"""
XSUAA Configuration:
{json.dumps(xs_security, indent=2)}

Detected Security Violations:
{json.dumps([{
    'rule': v.rule_id,
    'title': v.title,
    'description': v.description,
    'severity': v.severity,
    'impact': v.impact
} for v in violations], indent=2)}

User Query: {query}
"""
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": context}
                ],
                temperature=0.1,
                max_tokens=500
            )
            
            answer = response.choices[0].message.content.strip()
            
            # Determine query type
            query_lower = query.lower()
            if 'can' in query_lower and ('access' in query_lower or 'call' in query_lower):
                query_type = 'access_check'
            elif 'role' in query_lower:
                query_type = 'role_analysis'
            elif 'scope' in query_lower:
                query_type = 'scope_analysis'
            else:
                query_type = 'compliance_check'
            
            return AccessQuery(
                query=query,
                query_type=query_type,
                answer=answer,
                confidence=0.85  # Mock confidence score
            )
            
        except Exception as e:
            return AccessQuery(
                query=query,
                query_type='error',
                answer=f"Error analyzing query: {str(e)}",
                confidence=0.0
            )
    
    def generate_sample_xs_security(self, requirements: str) -> str:
        """Generate sample xs-security.json from requirements"""
        
        system_prompt = """You are an expert SAP XSUAA security architect. Generate a complete, production-ready xs-security.json configuration based on the requirements provided.

Include:
- Appropriate scopes with descriptive names
- Role templates that group related scopes
- OAuth2 configuration if needed
- Security attributes if applicable

Return ONLY valid JSON content, no markdown formatting."""
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Generate xs-security.json for: {requirements}"}
                ],
                temperature=0.3,
                max_tokens=1500
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            raise Exception(f"Failed to generate xs-security.json: {str(e)}")

# Convenience functions for the main app
def create_xsuaa_analyzers(openai_client):
    """Create XSUAA analyzer instances"""
    symbolic = XSUAASymbolicAnalyzer()
    neural = XSUAANeuralAnalyzer(openai_client)
    return symbolic, neural