# Azure Automation: Entra ID Device Cleanup Guidelines

## Project Overview
This Azure Automation solution automatically manages and cleans up inactive devices from your Entra ID (Azure Active Directory) tenant using Microsoft Graph API. The automation identifies devices that have been inactive for a specified period and performs appropriate cleanup operations based on device type.

## Core Requirements & Objectives

### Primary Goals
- Automatically identify and remove inactive devices from Entra ID
- Maintain separate handling for standard registered devices vs Autopilot devices
- Provide comprehensive audit trails and compliance reporting
- Implement safety mechanisms to prevent accidental mass deletions
- Enable user notifications before device removal

### Key Features to Implement
1. **Dual Device Type Handling**
   - Standard registered devices: Complete removal from Entra ID
   - Autopilot devices: Remove from Entra ID while preserving Autopilot enrollment

2. **Email Notification System**
   - Warning emails to device owners (7 days before deletion)
   - Final notices on deletion day
   - Confirmation emails post-deletion
   - Admin summary reports (daily/weekly/monthly)

3. **Safety & Control Mechanisms**
   - Configurable inactivity threshold (default: 90 days)
   - WhatIf/simulation mode for testing
   - Maximum deletion thresholds (percentage and absolute)
   - Device exclusion lists
   - Pre-deletion backups

4. **Compliance & Auditing**
   - Detailed logging of all actions
   - HTML compliance reports
   - Export capabilities for processed devices
   - Integration with Azure Monitor/Log Analytics

## Technical Architecture

### Azure Resources Required
- Azure Automation Account
- Managed Identity or Service Principal
- Azure Storage Account (for backups and reports)
- Log Analytics Workspace (optional but recommended)

### Required Graph API Permissions
| Permission | Type | Purpose |
|------------|------|---------|
| Device.ReadWrite.All | Application | Read and delete device objects |
| User.Read.All | Application | Read user information for notifications |
| Mail.Send | Application | Send email notifications |
| Directory.ReadWrite.All | Application | Modify directory objects |
| DeviceManagementServiceConfig.ReadWrite.All | Application | Access Autopilot information |

### PowerShell Modules Required
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.DeviceManagement.Enrollment

## Implementation Guidelines

### 1. Authentication Setup
- Use Managed Identity for production environments
- Support Service Principal authentication for testing
- Implement proper secret management using Azure Key Vault
- Validate all required permissions before execution

### 2. Device Identification Logic
The automation should follow this decision tree:
1. Query all devices from Entra ID
2. Check `ApproximateLastSignInDateTime` property
3. Calculate days since last sign-in
4. Apply exclusion rules (if configured)
5. Categorize devices by type (TrustType property)
6. Apply appropriate cleanup action

### 3. Safety Mechanisms
Implement these critical safety features:
- **Permission Validation**: Check all required permissions before starting
- **Threshold Checks**: Prevent deletion if exceeding configured limits
- **Exclusion Lists**: Support excluding by:
  - Device name patterns
  - Device IDs
  - Operating system types
  - Owner email addresses
- **Backup Before Delete**: Export device list to JSON before any deletions
- **Progressive Rollout**: Start with longer inactivity periods, gradually reduce

### 4. Notification System Design
Structure the email notification flow:
1. **7 Days Before Deletion**: Warning email with action required
2. **Day of Deletion**: Final notice
3. **After Deletion**: Confirmation email
4. **Admin Reports**: Consolidated summaries with statistics

Email content should include:
- Clear subject lines indicating urgency
- Device identification details
- Last sign-in date
- Required actions to prevent deletion
- Contact information for support

### 5. Error Handling Strategy
- Implement try-catch blocks for all critical operations
- Log all errors to Azure Monitor
- Send failure notifications to administrators
- Continue processing remaining devices even if some fail
- Maintain failed device list for manual review

### 6. Compliance Reporting
Generate comprehensive reports including:
- Executive summary with key metrics
- Detailed device lists (processed, excluded, failed)
- Compliance attestation details
- Audit trail information
- Success/failure statistics
- Graphs and visualizations where applicable

## Operational Procedures

### Initial Deployment
1. Start with WhatIf mode enabled
2. Run with 180-day inactivity threshold
3. Review results and adjust exclusions
4. Gradually reduce threshold (180 → 120 → 90 days)
5. Enable production mode after validation

### Scheduling Recommendations
- **Daily Runs**: For environments with high device turnover
- **Weekly Runs**: For most organizations
- **Monthly Runs**: For stable environments

Recommended schedule:
- Time: 2:00 AM local time (low activity period)
- Day: Tuesday-Thursday (avoid Mondays and Fridays)

### Monitoring & Alerting
Set up alerts for:
- Runbook failures
- Deletion threshold exceeded
- Permission errors
- Abnormal execution duration
- High failure rates

### Recovery Procedures
1. **Accidental Deletion Recovery**:
   - Devices remain in Entra ID Recycle Bin for 30 days
   - Use Graph API to restore deleted devices
   - Maintain backup JSON files for reference

2. **Rollback Strategy**:
   - Keep device backups for minimum 90 days
   - Document original device configurations
   - Test restoration procedures regularly

## Testing Guidelines

### Test Scenarios
1. **Permission Testing**: Validate with missing permissions
2. **Threshold Testing**: Exceed safety thresholds
3. **Exclusion Testing**: Verify exclusion rules work
4. **Email Testing**: Confirm notifications are sent
5. **Error Handling**: Simulate API failures
6. **Scale Testing**: Test with large device counts

### Validation Checklist
- [ ] All permissions properly configured
- [ ] WhatIf mode produces expected results
- [ ] Safety thresholds prevent mass deletion
- [ ] Exclusion lists properly honored
- [ ] Email notifications sent correctly
- [ ] Compliance reports generated
- [ ] Backup files created successfully
- [ ] Error handling works as expected

## Security Considerations

### Best Practices
1. **Least Privilege**: Grant only required permissions
2. **Audit Logging**: Enable comprehensive logging
3. **Access Control**: Limit who can modify automation
4. **Secret Management**: Use Key Vault for credentials
5. **Network Security**: Restrict automation account network access
6. **Compliance**: Ensure alignment with organizational policies

### Data Protection
- Encrypt backup files at rest
- Secure email communications
- Redact sensitive information in logs
- Implement data retention policies
- Regular security assessments

## Performance Optimization

### For Large Environments (10,000+ devices)
1. Implement pagination for API calls
2. Use parallel processing where possible
3. Batch operations to reduce API calls
4. Implement caching for user lookups
5. Optimize exclusion list checking
6. Consider splitting into multiple runbooks

### API Throttling Considerations
- Implement exponential backoff
- Respect Graph API rate limits
- Use batch endpoints where available
- Cache frequently accessed data
- Monitor API usage patterns

## Maintenance & Updates

### Regular Maintenance Tasks
- Review and update exclusion lists monthly
- Validate permissions quarterly
- Test recovery procedures semi-annually
- Update PowerShell modules as needed
- Review safety thresholds based on device growth

### Version Control
- Maintain runbook versions in source control
- Document all changes with clear commit messages
- Test updates in non-production first
- Keep rollback procedures ready
- Document breaking changes

## Support Documentation

### Common Issues & Solutions
| Issue | Possible Cause | Solution |
|-------|---------------|----------|
| No devices found | Permissions issue | Verify Device.Read permissions |
| Emails not sending | Mail.Send missing | Grant and consent Mail.Send |
| Autopilot access denied | Tenant not configured | Check Autopilot licensing |
| Mass deletion blocked | Safety threshold | Adjust threshold settings |
| Slow performance | Large device count | Implement pagination |

### Troubleshooting Steps
1. Check Azure Automation job logs
2. Verify Graph API permissions
3. Test with WhatIf mode
4. Review exclusion lists
5. Check network connectivity
6. Validate module versions

## Compliance & Governance

### Regulatory Considerations
- Ensure compliance with data retention policies
- Document all automated deletions
- Maintain audit trails for specified period
- Align with organizational governance
- Consider GDPR/privacy implications

### Reporting Requirements
- Monthly compliance attestation
- Quarterly effectiveness review
- Annual security assessment
- Incident reporting procedures
- Change management documentation

## Success Metrics

### Key Performance Indicators
- Reduction in inactive devices (target: 90%+)
- Automation success rate (target: 99%+)
- Average execution time
- Email delivery rate
- User response rate to warnings
- False positive rate (devices incorrectly marked)

### Business Value Metrics
- Reduced security attack surface
- Lower licensing costs
- Improved compliance posture
- Reduced manual effort
- Better device inventory accuracy

## Future Enhancements

### Potential Improvements
1. Machine learning for anomaly detection
2. Integration with ITSM platforms
3. Self-service portal for device management
4. Advanced analytics and dashboards
5. Multi-tenant support
6. Mobile app notifications
7. Predictive cleanup recommendations
8. Integration with other cleanup automations

## Production Security Requirements

### Critical Security Controls
1. **Authentication**: Use managed identity only in production
2. **Authorization**: Implement least-privilege access with RBAC
3. **Audit Logging**: Enable comprehensive logging to Log Analytics
4. **Data Protection**: Encrypt all reports and backups at rest
5. **Input Validation**: Validate all parameters and thresholds
6. **Error Handling**: Secure error reporting without credential exposure
7. **Safety Limits**: Enforce maximum deletion thresholds
8. **Change Control**: All modifications require approval workflow

### Required Validation Checks
- Permission verification before execution
- Safety threshold validation
- Device exclusion list processing
- Backup creation before any deletions
- Audit trail generation
- Error logging and alerting

### Compliance Considerations
- SOX: Maintain complete audit trails
- GDPR: Handle EU user data appropriately  
- HIPAA: Additional controls for healthcare environments
- SOC2: Document all security controls
- Industry-specific regulations as applicable

## Production Deployment Standards

### Infrastructure Requirements
- Dedicated Azure Automation Account for production
- Log Analytics workspace with minimum 90-day retention
- Azure Storage Account for encrypted report storage
- Azure Key Vault for sensitive configuration
- Network security groups restricting access
- Backup and disaster recovery procedures

### Operational Requirements
- 24/7 monitoring and alerting
- Documented escalation procedures
- Change management process
- Incident response plan
- Regular security assessments
- Staff training and access reviews

### Performance Requirements
- Maximum execution time: 2 hours
- Success rate target: 99%+
- Alert response time: 15 minutes
- Recovery time objective: 4 hours
- Recovery point objective: 24 hours

## Conclusion

This automation provides a comprehensive, production-ready solution for managing device lifecycle in Entra ID. Success depends on careful planning, gradual rollout, continuous monitoring, and strict adherence to security best practices.

**Security First**: Always prioritize security and compliance over speed of deployment. This automation handles sensitive organizational data and performs potentially destructive operations.

**Gradual Implementation**: Start conservatively with longer inactivity thresholds and smaller deletion limits. Gradually optimize based on organizational needs and operational experience.

**Continuous Monitoring**: Maintain vigilant monitoring of all automation activities. Security incidents can have significant business impact and regulatory consequences.

Remember: The goal is to maintain a clean, secure device environment while minimizing impact on legitimate users and maintaining the highest security standards throughout the process.