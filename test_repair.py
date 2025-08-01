#!/usr/bin/env python3
"""Test the repair function specifically"""

import os
import sys
sys.path.insert(0, '.')

from openai import OpenAI
from app import NeuralManifestGenerator, PolicyViolation

def test_repair():
    print("🧪 Testing Neural Repair Function")
    
    # Initialize
    api_key = "your-openai-api-key-here"
    client = OpenAI(api_key=api_key)
    generator = NeuralManifestGenerator(client)
    
    # Test manifest with violations
    manifest = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  replicas: 2
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
        image: nginx:latest"""
    
    # Create sample violations
    violations = [
        PolicyViolation(
            rule_id="labels-required",
            title="Missing Required Labels",
            description="Missing required labels: team, version",
            severity="medium",
            path="metadata.labels",
            suggested_fix="Add these labels: team: <value>, version: <value>"
        )
    ]
    
    requirements = "Deploy a simple test app"
    
    try:
        print("Testing repair function...")
        repaired_manifest, explanation = generator.repair_manifest(manifest, violations, requirements)
        print("✅ Repair function works!")
        print(f"Explanation: {explanation[:200]}...")
        print("Manifest includes team/version labels:", "team:" in repaired_manifest and "version:" in repaired_manifest)
        return True
        
    except Exception as e:
        print(f"❌ Repair test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_repair()