# Application Permission Auditor - Test Resource Cleanup Commands

## Resources Created During Testing

The following test resources were created and need to be cleaned up:

### Azure Resources
- **Automation Account**: `aa-apppermaudit-08191954` in resource group `test-rg`
- **System Managed Identity**: `b68066f9-bb03-4eff-8ea9-d4e87f362208` (automatically created with Automation Account)
- **Runbook**: `ApplicationPermissionAuditor` (deployed to the automation account)

### Microsoft Graph Permissions
The following 6 permissions were granted to the managed identity:
1. `Application.Read.All`
2. `Directory.Read.All`
3. `DelegatedPermissionGrant.Read.All`
4. `AppRoleAssignment.ReadWrite.All`
5. `AuditLog.Read.All`
6. `Mail.Send`

## Cleanup Commands

### Option 1: Complete Cleanup (Recommended)

```powershell
# Connect with Global Admin account
$TenantId = '87db06e7-f38e-4c01-b926-8291bfae4996'
$SubscriptionId = 'a8ed02f4-14f2-4930-9143-3b90e5a87e30'

Connect-AzAccount -TenantId $TenantId -SubscriptionId $SubscriptionId
Connect-MgGraph -TenantId $TenantId -Scopes 'Directory.ReadWrite.All'

# Remove Automation Account (this automatically removes managed identity, runbooks, and Graph permissions)
Remove-AzAutomationAccount -ResourceGroupName 'test-rg' -Name 'aa-apppermaudit-08191954' -Force

# Verify cleanup
Get-AzResource -ResourceGroupName 'test-rg' | Where-Object { $_.Name -like '*apppermaudit*' }
```

### Option 2: Azure Portal Cleanup

1. **Go to Azure Portal**: https://portal.azure.com
2. **Navigate to**: Resource Groups → `test-rg`
3. **Find**: Automation Account `aa-apppermaudit-08191954`
4. **Delete**: Click the automation account and select "Delete"
5. **Confirm**: Type the automation account name to confirm deletion

### Option 3: Azure CLI Cleanup

```bash
# Login to Azure
az login --tenant 87db06e7-f38e-4c01-b926-8291bfae4996

# Remove the automation account
az automation account delete \
  --resource-group test-rg \
  --name aa-apppermaudit-08191954 \
  --yes

# Verify cleanup
az resource list --resource-group test-rg --query "[?contains(name, 'apppermaudit')]"
```

## What Gets Automatically Cleaned Up

When you delete the Automation Account, the following are **automatically removed**:
- ✅ System Managed Identity (`b68066f9-bb03-4eff-8ea9-d4e87f362208`)
- ✅ All runbooks in the automation account (including `ApplicationPermissionAuditor`)
- ✅ All Microsoft Graph API permissions granted to the managed identity
- ✅ All schedules associated with the automation account
- ✅ All modules imported to the automation account

## Verification Commands

After cleanup, verify that all resources are removed:

```powershell
# Check for any remaining Application Permission Auditor resources
Get-AzResource | Where-Object { $_.Name -like '*apppermaudit*' -or $_.Name -like '*ApplicationPermission*' }

# Check if managed identity still exists (should return nothing)
Get-MgServicePrincipal -Filter "id eq 'b68066f9-bb03-4eff-8ea9-d4e87f362208'"

# List remaining resources in test-rg
Get-AzResource -ResourceGroupName 'test-rg'
```

## Important Notes

1. **Single Command Cleanup**: Removing the Automation Account is sufficient - it cascades to remove all associated resources
2. **No Manual Graph Permission Cleanup Needed**: When the managed identity is deleted, all its permissions are automatically revoked
3. **test-rg Resource Group**: May contain other resources, so only delete if empty after automation account removal
4. **No Data Loss**: This was a test environment - no production data will be affected

## Emergency Cleanup (If Portal/PowerShell Unavailable)

If you cannot access Azure Portal or PowerShell, you can also clean up via:

1. **Azure Mobile App**: Delete the automation account
2. **Azure Cloud Shell**: Use the same PowerShell commands above
3. **Azure REST API**: Send DELETE request to automation account endpoint

## Cleanup Verification Checklist

After running cleanup commands, verify:
- [ ] Automation Account `aa-apppermaudit-08191954` no longer exists
- [ ] No resources with 'apppermaudit' in the name remain
- [ ] Managed Identity `b68066f9-bb03-4eff-8ea9-d4e87f362208` no longer exists
- [ ] No unexpected charges appearing in Azure billing

## Estimated Cleanup Time

- **Automation Account Deletion**: 2-5 minutes
- **Managed Identity Cleanup**: Automatic (immediate)
- **Graph Permissions Revocation**: Automatic (immediate)
- **Total Time**: Under 5 minutes

---

**Cleanup Status**: ⏳ PENDING MANUAL EXECUTION  
**Priority**: High (to avoid ongoing test resource charges)  
**Risk**: Low (test environment only)  

*Created: August 19, 2025*  
*Environment: Azure Tenant 87db06e7-f38e-4c01-b926-8291bfae4996*