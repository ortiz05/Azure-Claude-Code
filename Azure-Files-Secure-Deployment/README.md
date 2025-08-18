# Secure Azure Files Deployment

Deploy Azure Files with enterprise-grade security controls following industry best practices and compliance standards.

## 🎯 Authentication Options

### ✅ Option 1: Manual Deployment (Recommended for Most Users)
Use your Global Admin account with OAuth authentication (browser prompt):

```powershell
# No setup required - just run the deployment script
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-secure-files" `
    -StorageAccountName "stgsecurefiles001" `
    -Location "East US 2"
```

### 🤖 Option 2: Service Principal Deployment (For Automation Only)
**ONLY use this if you need unattended/automated deployment (CI/CD, API calls, etc.)**

First, create a Service Principal:
```powershell
.\Onboard-AzureFiles-ServicePrincipal.ps1 `
    -TenantId "your-tenant-id" `
    -SubscriptionId "your-subscription-id"
```

Then use the generated deployment script with Service Principal authentication.

## 🚀 Quick Manual Deployment (Most Common)

## 🔐 Security Features

### Built-in Security Controls
- **HTTPS-only traffic** - Forces secure transport layer
- **TLS 1.2 minimum** - Ensures modern encryption standards
- **Shared key access disabled** - Forces Azure AD authentication
- **Public blob access disabled** - Prevents accidental exposure
- **Cross-tenant replication disabled** - Prevents data leakage
- **Soft delete enabled** - 30-day recovery window for deleted files
- **Blob versioning** - Complete audit trail of file changes
- **Network access controls** - VNet integration and IP restrictions

### Advanced Security Options
- **Customer-managed encryption** - Integration with Azure Key Vault
- **Azure AD authentication** - Identity-based file share access
- **Premium storage** - Enhanced performance and security features
- **Monitoring and logging** - Integration with Log Analytics
- **Backup configuration** - Ready for Azure Backup integration

## 📊 Parameters

### Required Parameters
| Parameter | Description | Requirements | Example |
|-----------|-------------|--------------|---------|
| `SubscriptionId` | Azure subscription ID | GUID format | `12345678-1234-1234-1234-123456789012` |
| `ResourceGroupName` | Resource group name | 1-90 characters, alphanumeric, periods, underscores, hyphens, parentheses | `rg-secure-files` |
| `StorageAccountName` | Storage account name | **3-24 characters, lowercase letters and numbers only, globally unique** | `stgsecurefiles001` |
| `Location` | Azure region | Valid Azure region name | `East US 2`, `West Europe`, `Southeast Asia` |

### Optional Parameters
| Parameter | Default | Requirements | Description |
|-----------|---------|--------------|-------------|
| `FileShareName` | `secure-fileshare` | 3-63 characters, lowercase letters, numbers, and hyphens only | Name of the file share |
| `SkuName` | `Standard_ZRS` | Valid SKU values | Storage redundancy (`Standard_LRS`, `Standard_ZRS`, `Premium_LRS`, etc.) |
| `AccessTier` | `Hot` | `Hot` or `Cool` | Storage access tier (Hot for frequently accessed, Cool for infrequent) |
| `FileShareQuotaGB` | `1024` | 1-102400 GB | File share quota in GB (affects billing) |
| `EnableIdentityBasedAuth` | `$true` | Boolean | Enable Azure AD authentication |
| `RequireHttpsTrafficOnly` | `$true` | Boolean | Force HTTPS-only access |
| `EnableBackup` | `$true` | Boolean | Configure for backup (manual setup required) |

### Network Security Parameters
| Parameter | Requirements | Description | Example |
|-----------|--------------|-------------|---------|
| `VirtualNetworkResourceGroup` | Valid resource group name | VNet resource group for private access | `rg-network` |
| `VirtualNetworkName` | Valid VNet name | Virtual network name for security enhancement | `vnet-corp` |
| `SubnetName` | Valid subnet name | Subnet name for storage service endpoint | `subnet-storage` |
| `AllowedIPRanges` | CIDR format array | Array of allowed IP ranges | `@("203.0.113.0/24", "198.51.100.0/24")` |

### Advanced Security Parameters
| Parameter | Requirements | Description | Example |
|-----------|--------------|-------------|---------|
| `KeyVaultName` | Valid Key Vault name | Key Vault for customer-managed encryption (recommended) | `kv-encryption-keys` |
| `LogAnalyticsWorkspaceName` | Valid workspace name | Log Analytics workspace for monitoring and diagnostics | `law-security-logs` |

## 🔧 Deployment Examples

### Basic Secure Deployment
```powershell
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-prod" `
    -StorageAccountName "stgfilesprod001" `
    -Location "East US 2"
```

### VNet-Integrated Deployment
```powershell
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-prod" `
    -StorageAccountName "stgfilesprod001" `
    -Location "East US 2" `
    -VirtualNetworkResourceGroup "rg-network" `
    -VirtualNetworkName "vnet-corp" `
    -SubnetName "subnet-storage"
```

### Premium Storage with Customer-Managed Encryption
```powershell
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-prod" `
    -StorageAccountName "stgfilesprod001" `
    -Location "East US 2" `
    -SkuName "Premium_ZRS" `
    -KeyVaultName "kv-encryption-keys" `
    -LogAnalyticsWorkspaceName "law-security-logs"
```

### IP-Restricted Deployment
```powershell
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-prod" `
    -StorageAccountName "stgfilesprod001" `
    -Location "East US 2" `
    -AllowedIPRanges @("203.0.113.0/24", "198.51.100.0/24")
```

### WhatIf Mode (Testing)
```powershell
.\Deploy-SecureAzureFiles.ps1 `
    -SubscriptionId "12345678-1234-1234-1234-123456789012" `
    -ResourceGroupName "rg-files-test" `
    -StorageAccountName "stgfilestest001" `
    -Location "East US 2" `
    -WhatIf
```

## 🔐 Required Permissions

The account running this script requires the following Azure RBAC roles:

### Minimum Required Roles
- **Storage Account Contributor** - To create and configure storage accounts
- **Network Contributor** - For VNet integration (if used)
- **Key Vault Contributor** - For customer-managed encryption (if used)
- **Log Analytics Contributor** - For monitoring configuration (if used)

### Recommended Role Assignment
```powershell
# Assign Storage Account Contributor at resource group level
New-AzRoleAssignment -ObjectId "user-or-service-principal-id" `
    -RoleDefinitionName "Storage Account Contributor" `
    -Scope "/subscriptions/subscription-id/resourceGroups/resource-group-name"
```

## 🏗️ Post-Deployment Configuration

### 1. Configure RBAC for File Share Access
```powershell
# Storage File Data SMB Share Contributor
New-AzRoleAssignment -ObjectId "user-id" `
    -RoleDefinitionName "Storage File Data SMB Share Contributor" `
    -Scope "/subscriptions/subscription-id/resourceGroups/rg-name/providers/Microsoft.Storage/storageAccounts/storage-name/fileServices/default/fileshares/share-name"

# Storage File Data SMB Share Reader
New-AzRoleAssignment -ObjectId "user-id" `
    -RoleDefinitionName "Storage File Data SMB Share Reader" `
    -Scope "/subscriptions/subscription-id/resourceGroups/rg-name/providers/Microsoft.Storage/storageAccounts/storage-name/fileServices/default/fileshares/share-name"
```

### 2. Mount File Share on Windows
```cmd
net use Z: \\storageaccountname.file.core.windows.net\filesharename /persistent:yes
```

### 3. Mount File Share on Linux
```bash
sudo mkdir /mnt/azurefiles
sudo mount -t cifs //storageaccountname.file.core.windows.net/filesharename /mnt/azurefiles -o vers=3.0,credentials=/path/to/creds,dir_mode=0777,file_mode=0777,serverino
```

### 4. Configure Azure Backup (Manual)
1. Create or use existing Recovery Services Vault
2. Navigate to Backup in the vault
3. Select Azure File share as workload
4. Choose the storage account and file share
5. Configure backup policy (daily/weekly retention)

## 🛡️ Security Best Practices

### Access Control
- **Use Azure AD authentication** instead of storage account keys
- **Implement least privilege access** with appropriate RBAC roles
- **Regular access reviews** to ensure proper permissions
- **Enable MFA** for administrative access

### Network Security
- **Use VNet integration** for production workloads
- **Implement firewall rules** to restrict IP access
- **Consider private endpoints** for maximum security
- **Monitor network access logs** for unusual patterns

### Data Protection
- **Enable soft delete** (configured automatically)
- **Configure backup** for business-critical data
- **Use customer-managed keys** for sensitive data
- **Implement data classification** and labeling

### Monitoring and Compliance
- **Enable diagnostic logging** to Log Analytics
- **Set up monitoring alerts** for security events
- **Regular security assessments** and audits
- **Document compliance** with organizational policies

## 📊 Monitoring and Alerting

### Key Metrics to Monitor
- **Storage capacity usage** - Track quota utilization
- **Transaction count** - Monitor access patterns
- **Authentication failures** - Detect potential security issues
- **Network traffic** - Unusual access patterns

### Recommended Alerts
```powershell
# Alert for high storage usage (85% of quota)
New-AzMetricAlertRuleV2 -Name "High Storage Usage" `
    -ResourceGroupName $ResourceGroupName `
    -TargetResourceId $StorageAccountId `
    -MetricName "UsedCapacity" `
    -Operator GreaterThan `
    -Threshold 85 `
    -WindowSize "PT5M" `
    -Frequency "PT1M"
```

### Log Analytics Queries
```kusto
// File share access patterns
StorageFileLogs
| where TimeGenerated > ago(24h)
| summarize RequestCount = count() by AuthenticationType, bin(TimeGenerated, 1h)
| render timechart

// Authentication failures
StorageFileLogs
| where TimeGenerated > ago(24h)
| where StatusCode >= 400
| summarize FailureCount = count() by StatusCode, CallerIpAddress
| order by FailureCount desc
```

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| **Storage account name already exists** | Storage account names must be globally unique |
| **VNet service endpoint not configured** | Script will automatically configure the service endpoint |
| **Key Vault access denied** | Ensure proper permissions on Key Vault for managed identity |
| **Mounting fails on Windows** | Check Windows credentials and firewall settings |
| **Authentication errors** | Verify Azure AD authentication is properly configured |

### Connectivity Testing
```powershell
# Test SMB connectivity
Test-NetConnection -ComputerName "storageaccountname.file.core.windows.net" -Port 445

# Test HTTPS connectivity  
Test-NetConnection -ComputerName "storageaccountname.file.core.windows.net" -Port 443
```

### Validation Scripts
```powershell
# Verify storage account configuration
Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName | 
    Select-Object StorageAccountName, EnableHttpsTrafficOnly, MinimumTlsVersion, AllowBlobPublicAccess

# Check file share properties
$Context = (Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName).Context
Get-AzStorageShare -Name $FileShareName -Context $Context | 
    Select-Object Name, QuotaGiB, LastModified
```

## 📚 Additional Resources

- [Azure Files Security Guide](https://docs.microsoft.com/en-us/azure/storage/files/storage-files-security)
- [Azure Files Identity-based Authentication](https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-auth-active-directory-enable)
- [Azure Storage Security Best Practices](https://docs.microsoft.com/en-us/azure/storage/blobs/security-recommendations)
- [Azure Files Backup](https://docs.microsoft.com/en-us/azure/backup/azure-file-share-backup-overview)

## 🔄 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024-01 | Initial release with enterprise security controls |

## 📞 Support

For issues and questions:
1. Review the troubleshooting section
2. Check Azure documentation links
3. Validate permissions and network configuration
4. Review deployment logs for specific error messages