# Basic-Deployment.ps1
# Example: Basic secure Azure Files deployment

# Basic deployment with default security settings
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-basic" `
    -StorageAccountName "stgfilesbasic001" `
    -Location "East US 2" `
    -FileShareName "company-files" `
    -FileShareQuotaGB 500

Write-Host "Basic deployment completed. Validating security configuration..." -ForegroundColor Yellow

# Validate the deployment
.\Validate-AzureFilesDeployment.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-basic" `
    -StorageAccountName "stgfilesbasic001" `
    -FileShareName "company-files"