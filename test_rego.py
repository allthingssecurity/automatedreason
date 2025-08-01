#!/usr/bin/env python3
"""Test script for Rego policy validation"""

import yaml
import json
from app import RegoPolicyValidator, PolicyViolation

def test_rego_validation():
    """Test Rego policy validation with sample manifests"""
    
    print("🧪 Testing Rego Policy Validation")
    print("=" * 50)
    
    # Initialize validator
    validator = RegoPolicyValidator()
    
    # Test manifest with violations
    test_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prod-test-app
  labels:
    app: test-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: test-container
        image: nginx:latest
        # Missing resource limits
        # Missing security context
---
apiVersion: v1
kind: Service
metadata:
  name: test-service
  # Missing required labels
spec:
  selector:
    app: test-app
  ports:
  - port: 80
    targetPort: 8080
"""
    
    print("Testing manifest with expected violations...")
    result = validator.validate_manifest(test_manifest)
    
    print(f"✅ Validation completed!")
    print(f"Is compliant: {result.is_compliant}")
    print(f"Compliance score: {result.compliance_score:.2f}")
    print(f"Violations found: {len(result.violations)}")
    
    for i, violation in enumerate(result.violations, 1):
        print(f"\n{i}. {violation.title}")
        print(f"   Rule ID: {violation.rule_id}")
        print(f"   Severity: {violation.severity}")
        print(f"   Description: {violation.description}")
        print(f"   Path: {violation.path}")
        print(f"   Fix: {violation.suggested_fix}")
    
    print("\n" + "=" * 50)
    
    # Test compliant manifest
    compliant_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: compliant-app
  labels:
    app: compliant-app
    version: "1.0"
    team: platform
spec:
  replicas: 3
  selector:
    matchLabels:
      app: compliant-app
  template:
    metadata:
      labels:
        app: compliant-app
        version: "1.0"
        team: platform
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
      containers:
      - name: app-container
        image: nginx:latest
        resources:
          limits:
            cpu: "1000m"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "1Gi"
      - name: audit-logger
        image: audit-logger:latest
        resources:
          limits:
            cpu: "100m"
            memory: "128Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: compliant-service
  labels:
    app: compliant-app
    version: "1.0"
    team: platform
spec:
  selector:
    app: compliant-app
  ports:
  - port: 80
    targetPort: 8080
"""
    
    print("Testing compliant manifest...")
    result2 = validator.validate_manifest(compliant_manifest)
    
    print(f"✅ Validation completed!")
    print(f"Is compliant: {result2.is_compliant}")
    print(f"Compliance score: {result2.compliance_score:.2f}")
    print(f"Violations found: {len(result2.violations)}")
    
    if result2.violations:
        for i, violation in enumerate(result2.violations, 1):
            print(f"\n{i}. {violation.title}")
            print(f"   Rule ID: {violation.rule_id}")
            print(f"   Severity: {violation.severity}")
            print(f"   Description: {violation.description}")

if __name__ == "__main__":
    test_rego_validation()