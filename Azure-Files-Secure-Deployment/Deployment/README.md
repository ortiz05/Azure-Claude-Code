# Azure Files Secure Deployment Scripts

This folder contains all deployment-related scripts for the Azure Files Secure Deployment solution.

## Deployment Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| **Create-AzureFilesDeploymentGroup.ps1** | Creates Azure AD security group with required permissions for deployment | Run first to create deployment group |
| **Deploy-SecureAzureFiles.ps1** | Main deployment script for secure Azure Files infrastructure | Primary deployment tool |
| **Onboard-AzureFiles-ServicePrincipal.ps1** | Onboards service principals to the deployment group | Service principal management |
| **Validate-AzureFilesDeployment.ps1** | Validates successful deployment and security configuration | Post-deployment validation |

## Deployment Workflow

1. **Create Deployment Group**: `.\Create-AzureFilesDeploymentGroup.ps1`
2. **Onboard Service Principal**: `.\Onboard-AzureFiles-ServicePrincipal.ps1` (if using automation)
3. **Deploy Infrastructure**: `.\Deploy-SecureAzureFiles.ps1`
4. **Validate Deployment**: `.\Validate-AzureFilesDeployment.ps1`

## Security Notes

- All scripts implement least-privilege access patterns
- Deployment group provides scoped permissions instead of requiring Global Admin
- Infrastructure is deployed with security-first defaults (HTTPS-only, TLS 1.2, etc.)
- Public access is automatically restricted after provisioning

For detailed documentation, see the main README.md and Documentation/CLAUDE.md files.