
<#
.SYNOPSIS
    This runbook will stop an ARM VM in response to an Azure alert trigger.

.DESCRIPTION
    This runbook will stop an ARM VM in response to an Azure alert trigger.
    https://docs.microsoft.com/en-us/azure/automation/automation-create-alert-triggered-runbook
    Input is alert data with information needed to identify which VM to stop.

    DEPENDENCIES
    - The runbook must be called from an Azure alert via a webhook.
    - Latest version of Az module should be added to the automation account
      https://docs.microsoft.com/en-us/azure/automation/automation-update-azure-modules#update-az-modules

    REQUIRED AUTOMATION ASSETS
    - Managed Identity should be enabled and contributor access to the automation account should be given
      https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
      https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal?tabs=current
    - If User-Assigned Managed Identity is enabled, variable named "AUTOMATION_VMALERT_USER_ASSIGNED_IDENTITY_ID" should be added with client id

.PARAMETER WebhookData
    Optional (user should not enter anything, but the webhook service will always pass an object)
    This is the data that is sent in the webhook that is triggered from the alert.

.NOTES
    AUTHOR: Azure Automation Team 
    LASTEDIT: 2021-10-28
#>

[OutputType("PSAzureOperationResponse")]

param 
(
    [Parameter (Mandatory=$false)]
    [object] $WebhookData
)

$ErrorActionPreference = "stop"

if ($WebhookData) 
{ 
    # Get the data object from WebhookData
    $WebhookBody = (ConvertFrom-Json -InputObject $WebhookData.RequestBody)

    # Get the info needed to identify the VM (depends on the payload schema)
    $schemaId = $WebhookBody.schemaId
    Write-Verbose "schemaId: $schemaId" -Verbose
    if ($schemaId -eq "azureMonitorCommonAlertSchema") {
        # This is the common Metric Alert schema (released March 2019)
        $Essentials = [object] ($WebhookBody.data).essentials
        # Get the first target only as this script doesn''t handle multiple
        $alertTargetIdArray = (($Essentials.alertTargetIds)[0]).Split("/")
        $SubId = ($alertTargetIdArray)[2]
        $ResourceGroupName = ($alertTargetIdArray)[4]
        $ResourceType = ($alertTargetIdArray)[6] + "/" + ($alertTargetIdArray)[7]
        $ResourceName = ($alertTargetIdArray)[-1]
        $status = $Essentials.monitorCondition
    }
    elseif ($schemaId -eq "AzureMonitorMetricAlert") {
        # This is the near-real-time Metric Alert schema
        $AlertContext = [object] ($WebhookBody.data).context
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = $AlertContext.resourceName
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq "Microsoft.Insights/activityLogs") {
        # This is the Activity Log Alert schema
        $AlertContext = [object] (($WebhookBody.data).context).activityLog
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = (($AlertContext.resourceId).Split("/"))[-1]
        $status = ($WebhookBody.data).status
    }
    elseif ($schemaId -eq $null) {
        # This is the original Metric Alert schema
        $AlertContext = [object] $WebhookBody.context
        $SubId = $AlertContext.subscriptionId
        $ResourceGroupName = $AlertContext.resourceGroupName
        $ResourceType = $AlertContext.resourceType
        $ResourceName = $AlertContext.resourceName
        $status = $WebhookBody.status
    }
    else {
        # Schema not supported
        Write-Error "The alert data schema - $schemaId - is not supported."
    }

    Write-Verbose "status: $status" -Verbose
    if (($status -eq "Activated") -or ($status -eq "Fired"))
    {
        Write-Verbose "resourceType: $ResourceType" -Verbose
        Write-Verbose "resourceName: $ResourceName" -Verbose
        Write-Verbose "resourceGroupName: $ResourceGroupName" -Verbose
        Write-Verbose "subscriptionId: $SubId" -Verbose

        # Determine code path depending on the resourceType
        if ($ResourceType -eq "Microsoft.Compute/virtualMachines")
        {
            # This is an ARM VM
            Write-Verbose "This is an ARM VM." -Verbose

            #Authenticate to Azure with MSI and set subscription
            Write-Verbose "Authenticating to Azure with Managed Identity" -Verbose
            # Ensures you do not inherit an AzContext in your runbook
            Disable-AzContextAutosave -Scope Process

            $ClientId = Get-AutomationVariable -Name "AUTOMATION_VMALERT_USER_ASSIGNED_IDENTITY_ID" -ErrorAction SilentlyContinue
            if($ClientId)
            {
                # Connect to Azure with user-assigned managed identity
                $AzureContext = (Connect-AzAccount -Identity -AccountId $ClientId).context
            }
            else
            {
                # Connect to Azure with system-assigned managed identity
                $AzureContext = (Connect-AzAccount -Identity).context
            }
            $AzureContext = Set-AzContext -Subscription $SubId -DefaultProfile $AzureContext
            Write-Verbose "Subscription to work against: $SubId" -Verbose

            # Stop the ARM VM
            Write-Verbose "Stopping the VM - $ResourceName - in resource group - $ResourceGroupName -" -Verbose
            Stop-AzVM -Name $ResourceName -ResourceGroupName $ResourceGroupName -DefaultProfile $AzureContext -Force
            # [OutputType(PSAzureOperationResponse")]
        }
        else {
            # ResourceType not supported
            Write-Error "$ResourceType is not a supported resource type for this runbook."
        }
    }
    else {
        # The alert status was not ''Activated'' or ''Fired'' so no action taken
        Write-Verbose ("No action taken. Alert status: " + $status) -Verbose
    }
}
else {
    # Error
    Write-Error "This runbook is meant to be started from an Azure alert webhook only." 
}
