package sap.k8s.security

deny[msg] {
    input.kind == "Deployment"
    input.spec.replicas < 2
    contains(input.metadata.name, "prod")
    msg := "Production deployments must have at least 2 replicas"
}
