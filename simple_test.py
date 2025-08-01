#!/usr/bin/env python3
"""Simple test of the neural manifest generator"""

import os
import sys
sys.path.insert(0, '.')

from openai import OpenAI
from app import NeuralManifestGenerator

def test_neural_generator():
    print("🧪 Testing Neural Manifest Generator")
    
    # Initialize
    api_key = "your-openai-api-key-here"
    client = OpenAI(api_key=api_key)
    generator = NeuralManifestGenerator(client)
    
    # Test requirements
    requirements = """Deploy a simple web application:
- Service name: test-app
- Environment: development  
- Resources: 1 CPU core, 2GB RAM
- Replicas: 2
"""
    
    try:
        print("Generating manifest...")
        manifest = generator.generate_manifest(requirements)
        print("✅ Manifest generated successfully!")
        print(f"Manifest length: {len(manifest)} characters")
        print("First 500 characters:")
        print(manifest[:500])
        return True
        
    except Exception as e:
        print(f"❌ Generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_neural_generator()