# Rego Policy Validation Flow - Interactive Demo

An interactive demonstration of Kubernetes policy validation using OPA/Rego and Neuro-Symbolic AI. This demo shows how LLMs generate Kubernetes manifests, how Rego policies validate them, and how the generator-verifier loop works to create compliant configurations.

## 🚀 Live Demo

Visit the live demo: [Your GitHub Pages URL will be here]

## 🎯 Features

- **Interactive Tabbed Interface**: Switch between Basic and Enterprise scenarios
- **Animated Flow Visualization**: Watch the 6-step validation process
- **Real Policy Examples**: Based on actual SAP production policies
- **Two Scenarios**:
  - **Basic K8s Deployment**: Simple nginx deployment with common violations
  - **SAP Enterprise Workload**: Complex CAP service with enterprise requirements

## 🛠️ Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Policies**: OPA/Rego policy language
- **AI**: OpenAI GPT-4 for manifest generation
- **Deployment**: GitHub Pages
- **Architecture**: Neuro-Symbolic AI approach

## 📋 Demo Flow

### 6-Step Validation Process

1. **📝 User Requirements** - Natural language input
2. **🧠 Neural AI Generation** - LLM generates K8s manifest
3. **🛡️ Rego Policy Validation** - OPA validates against policies
4. **🔧 Automated Repair** - AI fixes violations
5. **✅ Final Validation** - Compliance verification
6. **🚀 Production Ready** - Deployment-ready manifest

## 🏗️ Local Development

1. Clone this repository
2. Open `index.html` in your browser
3. No build process required - pure HTML/CSS/JS

## 🌐 GitHub Pages Deployment

### Option 1: Automatic Deployment

1. Fork this repository
2. Go to Settings → Pages
3. Select "Deploy from a branch"
4. Choose "main" branch and "/ (root)" folder
5. Your demo will be available at `https://yourusername.github.io/repo-name`

### Option 2: Manual Upload

1. Download all files
2. Create a new GitHub repository
3. Upload files to the repository
4. Enable GitHub Pages in repository settings

## 📁 File Structure

```
├── index.html          # Main demo page with tabbed interface
├── demo1.html          # Legacy single demo (optional)
├── demo2.html          # Can be created for additional demos
├── README.md           # This file
└── policies/
    └── opa/
        └── sap-k8s-policies.rego  # Actual Rego policies used
```

## 🔧 Policy Examples

The demo includes real SAP production policies:

- **Resource Limits**: Containers must specify CPU/memory limits
- **Required Labels**: app, version, team labels mandatory
- **High Availability**: Production deployments need 2+ replicas
- **Security Context**: Containers must run as non-root
- **Audit Logging**: Production services need audit sidecars
- **Data Residency**: EU deployments need data-residency labels
- **Network Policies**: Enterprise deployments need network policies

## 🎨 Customization

### Adding New Scenarios

1. Edit the `demoData` object in `index.html`
2. Add new tab in the navigation
3. Define steps, manifests, violations, and repairs

### Modifying Policies

1. Update the violations arrays in the demo data
2. Modify the Rego policies in `policies/opa/`
3. Adjust the repair logic to match new policies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test the demo locally
5. Submit a pull request

## 📄 License

This project is open source and available under the MIT License.

## 🔗 Related Projects

- [OPA/Rego Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Kubernetes Policy Management](https://kubernetes.io/docs/concepts/policy/)
- [SAP Cloud Application Programming Model](https://cap.cloud.sap/)

## 📞 Support

For questions or issues:
- Open a GitHub issue
- Check the demo functionality in different browsers
- Ensure JavaScript is enabled

---

**Built with ❤️ for demonstrating modern cloud-native security practices**