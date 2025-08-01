#!/usr/bin/env python3
"""
XSUAA Neuro-Symbolic Policy Engine
Translates natural language queries to logical policy evaluation
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from openai import OpenAI

@dataclass
class LogicalQuery:
    """Represents a logical query for XSUAA policy evaluation"""
    user_id: str
    action: str  # 'READ', 'WRITE', 'EXECUTE', etc.
    resource: str  # endpoint or resource path
    context: Dict[str, Any]  # additional context like IP, time, etc.
    
@dataclass 
class PolicyDecision:
    """Result of policy evaluation"""
    allowed: bool
    reason: str
    applicable_roles: List[str]
    applicable_scopes: List[str]
    confidence: float

class XSUAANeuralTranslator:
    """Neural component that translates natural language to logical queries"""
    
    def __init__(self, openai_client):
        self.client = openai_client
        
    def translate_query(self, natural_query: str, context: Dict = None) -> LogicalQuery:
        """Translate natural language query to logical representation"""
        
        system_prompt = """You are an expert XSUAA policy translator. Convert natural language access questions into structured logical queries.

Extract these components from the query:
1. user_id: The user/subject requesting access
2. action: The action type (READ, WRITE, DELETE, EXECUTE, APPROVE, etc.)
3. resource: The resource/endpoint being accessed (like '/api/payments', '/users', 'invoice-service', etc.)
4. context: Any additional context (IP, time constraints, etc.)

Return ONLY a JSON object with these fields. No markdown formatting.

Examples:
"Can user john.doe access the payments API?" 
→ {"user_id": "john.doe", "action": "READ", "resource": "/api/payments", "context": {}}

"Is alice allowed to delete invoices from the finance system?"
→ {"user_id": "alice", "action": "DELETE", "resource": "/finance/invoices", "context": {}}
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Query: {natural_query}"}
                ],
                temperature=0.1,
                max_tokens=200
            )
            
            result = json.loads(response.choices[0].message.content.strip())
            
            return LogicalQuery(
                user_id=result.get('user_id', ''),
                action=result.get('action', 'READ').upper(),
                resource=result.get('resource', ''),
                context=result.get('context', {})
            )
            
        except Exception as e:
            # Fallback simple parsing
            return self._simple_parse(natural_query)
    
    def _simple_parse(self, query: str) -> LogicalQuery:
        """Fallback simple parsing when LLM fails"""
        query_lower = query.lower()
        
        # Extract user
        user_match = re.search(r'user\s+(\w+(?:\.\w+)?)', query_lower)
        user_id = user_match.group(1) if user_match else 'unknown'
        
        # Extract action
        action = 'READ'
        if any(word in query_lower for word in ['delete', 'remove']):
            action = 'DELETE'
        elif any(word in query_lower for word in ['write', 'create', 'update', 'modify']):
            action = 'WRITE'
        elif any(word in query_lower for word in ['execute', 'run']):
            action = 'EXECUTE'
        elif any(word in query_lower for word in ['approve']):
            action = 'APPROVE'
            
        # Extract resource
        resource_match = re.search(r'(/\w+(?:/\w+)*|\w+-?\w*\s*(?:api|service|endpoint))', query_lower)
        resource = resource_match.group(1) if resource_match else '/unknown'
        
        return LogicalQuery(
            user_id=user_id,
            action=action,
            resource=resource,
            context={}
        )

class XSUAASymbolicEvaluator:
    """Symbolic engine that evaluates logical queries against XSUAA policies"""
    
    def __init__(self):
        pass
        
    def evaluate_access(self, query: LogicalQuery, xs_security: Dict, user_roles: List[str] = None) -> PolicyDecision:
        """Evaluate if access should be granted based on XSUAA policies"""
        
        if not user_roles:
            user_roles = self._infer_user_roles(query.user_id, xs_security)
        
        # Get all scopes for user's roles
        user_scopes = self._get_user_scopes(user_roles, xs_security)
        
        # Check if user has required scope for this action/resource
        required_scopes = self._determine_required_scopes(query, xs_security)
        
        # Evaluate access
        allowed_scopes = set(user_scopes) & set(required_scopes)
        
        if allowed_scopes:
            return PolicyDecision(
                allowed=True,
                reason=f"User has required scopes: {', '.join(allowed_scopes)}",
                applicable_roles=user_roles,
                applicable_scopes=list(allowed_scopes),
                confidence=0.9
            )
        else:
            return PolicyDecision(
                allowed=False,
                reason=f"User lacks required scopes. Has: {user_scopes}, Needs: {required_scopes}",
                applicable_roles=user_roles,
                applicable_scopes=[],
                confidence=0.9
            )
    
    def _infer_user_roles(self, user_id: str, xs_security: Dict) -> List[str]:
        """Get user roles from xs-security users mapping or infer from patterns"""
        
        # Option A: Check if users are defined in xs-security.json
        users = xs_security.get('users', {})
        if user_id in users:
            return users[user_id]
        
        # Fallback: Infer from username patterns for demo
        user_lower = user_id.lower()
        
        roles = []
        if 'admin' in user_lower:
            roles.append('Administrator')
        elif 'finance' in user_lower or 'accounting' in user_lower:
            roles.append('FinanceManager')
        elif 'audit' in user_lower:
            roles.append('Auditor')
        elif 'manager' in user_lower:
            roles.append('FinanceManager')
        else:
            roles.append('Accountant')  # Default role
            
        return roles
    
    def _get_user_scopes(self, user_roles: List[str], xs_security: Dict) -> List[str]:
        """Get all scopes available to user through their roles"""
        user_scopes = set()
        
        for role_template in xs_security.get('role-templates', []):
            if role_template.get('name') in user_roles:
                user_scopes.update(role_template.get('scope-references', []))
        
        return list(user_scopes)
    
    def _determine_required_scopes(self, query: LogicalQuery, xs_security: Dict) -> List[str]:
        """Determine what scopes are required for this action/resource"""
        required_scopes = []
        
        # Map actions to scope patterns
        action_mapping = {
            'READ': ['read', 'view', 'display'],
            'WRITE': ['write', 'create', 'update', 'modify'],
            'DELETE': ['delete', 'remove'],
            'EXECUTE': ['execute', 'run'],
            'APPROVE': ['approve', 'authorize']
        }
        
        # Map resources to scope patterns  
        resource_patterns = {
            'payment': ['payment', 'finance'],
            'invoice': ['invoice', 'billing'],
            'user': ['user', 'identity'],
            'report': ['report', 'analytics'],
            'admin': ['admin', 'system']
        }
        
        # Look for matching scopes based on action
        action_patterns = action_mapping.get(query.action, [])
        
        # Look for matching scopes based on resource
        resource_keywords = []
        for keyword, patterns in resource_patterns.items():
            if keyword in query.resource.lower():
                resource_keywords.extend(patterns)
        
        # Find scopes that match action + resource patterns
        for scope in xs_security.get('scopes', []):
            scope_name = scope.get('name', '').lower()
            
            # Check if scope matches action pattern
            action_match = any(pattern in scope_name for pattern in action_patterns)
            # Check if scope matches resource pattern  
            resource_match = any(pattern in scope_name for pattern in resource_keywords) if resource_keywords else True
            
            if action_match and resource_match:
                required_scopes.append(scope.get('name'))
        
        # Fallback: if no specific scopes found, look for general patterns
        if not required_scopes:
            general_patterns = action_patterns + (resource_keywords if resource_keywords else [])
            for scope in xs_security.get('scopes', []):
                scope_name = scope.get('name', '').lower()
                if any(pattern in scope_name for pattern in general_patterns):
                    required_scopes.append(scope.get('name'))
        
        return required_scopes

class XSUAAPolicyEngine:
    """Main engine that combines neural translation with symbolic evaluation"""
    
    def __init__(self, openai_client):
        self.neural = XSUAANeuralTranslator(openai_client)
        self.symbolic = XSUAASymbolicEvaluator()
    
    def evaluate_natural_query(self, natural_query: str, xs_security: Dict, user_roles: List[str] = None) -> Tuple[LogicalQuery, PolicyDecision]:
        """Main entry point: natural language → logical query → policy decision"""
        
        # Step 1: Neural translation
        logical_query = self.neural.translate_query(natural_query)
        
        # Step 2: Symbolic evaluation
        decision = self.symbolic.evaluate_access(logical_query, xs_security, user_roles)
        
        return logical_query, decision

# Convenience function for main app
def create_xsuaa_policy_engine(openai_client):
    """Create XSUAA policy engine instance"""
    return XSUAAPolicyEngine(openai_client)