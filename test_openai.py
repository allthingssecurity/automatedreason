#!/usr/bin/env python3
"""Test OpenAI API connectivity"""

import os
from openai import OpenAI

def test_openai():
    api_key = "your-openai-api-key-here"
    
    try:
        print("Testing OpenAI API connection...")
        client = OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": "Hello, generate a simple YAML deployment"}
            ],
            max_tokens=100,
            timeout=10
        )
        
        print("✅ OpenAI API test successful!")
        print(f"Response: {response.choices[0].message.content[:200]}...")
        return True
        
    except Exception as e:
        print(f"❌ OpenAI API test failed: {e}")
        return False

if __name__ == "__main__":
    test_openai()