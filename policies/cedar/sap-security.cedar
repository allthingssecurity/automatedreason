permit(principal, action, resource)
when {
    resource.kind == "Deployment" &&
    resource.metadata.namespace == "production"
    implies
    resource.spec.template.spec.containers.all(c => 
        c.securityContext.runAsNonRoot == true
    )
}
