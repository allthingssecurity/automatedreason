#!/bin/bash

# Script to automatically enable GitHub Pages
echo "🚀 Enabling GitHub Pages for allthingssecurity/automatedreason..."

# Get the repository info
REPO_OWNER="allthingssecurity"
REPO_NAME="automatedreason"

# Enable GitHub Pages using GitHub CLI (if available)
if command -v gh &> /dev/null; then
    echo "📡 Using GitHub CLI to enable Pages..."
    gh api \
        --method POST \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        /repos/$REPO_OWNER/$REPO_NAME/pages \
        -f source='{"branch":"main","path":"/"}'
    
    echo "✅ GitHub Pages enabled!"
    echo "🌐 Your site will be available at: https://$REPO_OWNER.github.io/$REPO_NAME/"
else
    echo "❌ GitHub CLI not found. Please install it or enable Pages manually."
    echo "📖 Manual steps:"
    echo "   1. Go to https://github.com/$REPO_OWNER/$REPO_NAME/settings/pages"
    echo "   2. Under 'Source', select 'GitHub Actions'"
    echo "   3. Save the settings"
fi