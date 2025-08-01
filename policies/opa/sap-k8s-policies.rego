package sap.k8s.security

# SAP Kubernetes Security Policies
# This policy package validates Kubernetes manifests against SAP production standards

import rego.v1

# Resource limits policy
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits
    msg := {
        "rule_id": "resource-limits",
        "title": "Missing Resource Limits",
        "description": "Containers must specify CPU and memory limits for production",
        "severity": "high",
        "path": "spec.template.spec.containers[].resources.limits",
        "suggested_fix": "Add resource limits: cpu: '2000m', memory: '4Gi'"
    }
}

# EU Data residency policy
deny contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    labels := input.metadata.labels
    labels.region
    startswith(labels.region, "eu")
    not labels["data-residency"]
    msg := {
        "rule_id": "data-residency",
        "title": "Missing Data Residency Label",
        "description": "EU deployments must have data-residency label",
        "severity": "high",
        "path": "metadata.labels.data-residency",
        "suggested_fix": "Add label: data-residency: EU"
    }
}

# High availability policy
deny contains msg if {
    input.kind == "Deployment"
    replicas := input.spec.replicas
    replicas < 2
    contains(input.metadata.name, "prod")
    msg := {
        "rule_id": "high-availability",
        "title": "Insufficient Replicas for HA",
        "description": "Production deployments require at least 2 replicas",
        "severity": "medium",
        "path": "spec.replicas",
        "suggested_fix": "Set replicas: 3 for proper HA"
    }
}

# Security context policy
deny contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    security_context := input.spec.template.spec.securityContext
    security_context.runAsRoot == true
    msg := {
        "rule_id": "security-context",
        "title": "Running as Root",
        "description": "Containers should not run as root user",
        "severity": "high",
        "path": "spec.template.spec.securityContext.runAsNonRoot",
        "suggested_fix": "Set runAsNonRoot: true and runAsUser: 1001"
    }
}

# Required labels policy
deny contains msg if {
    input.kind in ["Deployment", "Service"]
    labels := input.metadata.labels
    required := {"app", "version", "team"}
    missing := required - {key | labels[key]}
    count(missing) > 0
    missing_list := [label | label := missing[_]]
    msg := {
        "rule_id": "labels-required",
        "title": "Missing Required Labels",
        "description": sprintf("Missing required labels: %s", [concat(", ", missing_list)]),
        "severity": "medium",
        "path": "metadata.labels",
        "suggested_fix": sprintf("Add these labels: %s", [concat(", ", [sprintf("%s: <value>", [label]) | label := missing_list[_]])])
    }
}

# Audit logging policy
deny contains msg if {
    input.kind == "Deployment"
    containers := input.spec.template.spec.containers
    not has_audit_sidecar(containers)
    count(containers) == 1  # Only main container, no sidecar
    msg := {
        "rule_id": "audit-logging",
        "title": "Missing Audit Logging Sidecar",
        "description": "Production services must include audit logging sidecar",
        "severity": "high",
        "path": "spec.template.spec.containers",
        "suggested_fix": "Add audit-logger sidecar container"
    }
}

# Helper function to check for audit sidecar
has_audit_sidecar(containers) if {
    container := containers[_]
    contains(container.name, "audit")
}

has_audit_sidecar(containers) if {
    container := containers[_]
    contains(container.name, "logging")
}

# Network policy requirement
deny contains msg if {
    input.kind == "Deployment"
    labels := input.metadata.labels
    labels.environment == "production"
    not has_network_policy_annotation(input.metadata.annotations)
    msg := {
        "rule_id": "network-policy",
        "title": "Missing Network Policy",
        "description": "Production deployments should have network policies",
        "severity": "medium",
        "path": "metadata.annotations",
        "suggested_fix": "Add annotation: networking.sap.com/policy: 'required'"
    }
}

has_network_policy_annotation(annotations) if {
    annotations["networking.sap.com/policy"]
}