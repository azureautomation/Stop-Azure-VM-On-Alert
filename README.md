# Start-VM-On-AzureAlert
- This runbook will stop an ARM VM in response to an Azure alert trigger 
- Input is alert data with information needed to identify which VM to stop.  
- The runbook must be called from an Azure alert via a webhook  
- Latest version of Az module should be added to the automation account  
- Managed Identity should be enabled and contributor access to the automation account should be given
