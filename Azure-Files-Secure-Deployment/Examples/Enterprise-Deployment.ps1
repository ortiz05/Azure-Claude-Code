# Enterprise-Deployment.ps1
# Example: Enterprise-grade Azure Files deployment with full security features

# Enterprise deployment with all security features
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-enterprise" `
    -StorageAccountName "stgfilesenterprise001" `
    -Location "East US 2" `
    -FileShareName "enterprise-data" `
    -SkuName "Premium_ZRS" `
    -AccessTier "Hot" `
    -FileShareQuotaGB 2048 `
    -VirtualNetworkResourceGroup "rg-network-prod" `
    -VirtualNetworkName "vnet-corp-prod" `
    -SubnetName "subnet-storage" `
    -AllowedIPRanges @("203.0.113.0/24", "198.51.100.0/24") `
    -KeyVaultName "kv-enterprise-encryption" `
    -LogAnalyticsWorkspaceName "law-enterprise-security" `
    -EnableBackup `
    -EnableIdentityBasedAuth `
    -RequireHttpsTrafficOnly

Write-Host "Enterprise deployment completed. Validating security configuration..." -ForegroundColor Yellow

# Validate the deployment
.\Validate-AzureFilesDeployment.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-enterprise" `
    -StorageAccountName "stgfilesenterprise001" `
    -FileShareName "enterprise-data"

Write-Host "`nNext steps for enterprise deployment:" -ForegroundColor Cyan
Write-Host "1. Configure RBAC permissions for file share access" -ForegroundColor Gray
Write-Host "2. Set up Azure Backup for the file share" -ForegroundColor Gray
Write-Host "3. Configure monitoring alerts in Azure Monitor" -ForegroundColor Gray
Write-Host "4. Test connectivity from client systems" -ForegroundColor Gray
Write-Host "5. Document access procedures for end users" -ForegroundColor Gray