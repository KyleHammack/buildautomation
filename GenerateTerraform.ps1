param(
    [string] $buildfile,
    [string] $templatesdirpath,
    [string] $outputdirpath
)

<#
# Function for setting proper JSON formatting
# https://github.com/PowerShell/PowerShell/issues/2736#issue-190538839
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
  $indent = 0;
  ($json -Split '\n' |
    ForEach-Object {
      if ($_ -match '[\}\]]') {
        # This line contains  ] or }, decrement the indentation level
        $indent--
      }
      $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
      if ($_ -match '[\{\[]') {
        # This line contains [ or {, increment the indentation level
        $indent++
      }
      $line
  }) -Join "`n"
}
#>

# Pre-Define Collection Variables
$json = New-Object -TypeName psobject
$resources = New-Object -TypeName psobject
$datasources = New-Object -TypeName psobject
$omsresources = New-Object -TypeName psobject
$aaresources = New-Object -TypeName psobject
$omslinkedserviceresources = New-Object -TypeName psobject
$omssolutionsresources = New-Object -TypeName psobject
$rsvresources = New-Object -TypeName psobject
$vmprotectionpolicyresources = New-Object -TypeName psobject
$nsgresources = New-Object -TypeName psobject
$vnetresources = New-Object -TypeName psobject
$subnetdatasources = New-Object -TypeName psobject
$outputs = New-Object -TypeName psobject
$ridresources = New-Object -TypeName psobject
$saresources = New-Object -TypeName psobject
$rgresources = New-Object -TypeName psobject
$avsetresources = New-Object -TypeName psobject
$nicresources = New-Object -TypeName psobject
$vmresources = New-Object -TypeName psobject
$vmextresources = New-Object -TypeName psobject
$vmbackupresources = New-Object -TypeName psobject
$armdeployresources = New-Object -TypeName psobject
$lbresources = New-Object -TypeName psobject
$lbruleresources = New-Object -TypeName psobject
$lbbepoolresources = New-Object -TypeName psobject
$lbproberesources = New-Object -TypeName psobject
$pipresources = New-Object -TypeName psobject
$appgwvmassocresources = New-Object -TypeName psobject
$appgwresources = New-Object -TypeName psobject
$vpngwresources = New-Object -TypeName psobject
$localgwresources = New-Object -TypeName psobject
$gwconnresources = New-Object -TypeName psobject
$sqlserverresources = New-Object -TypeName psobject
$sqlfwruleresources = New-Object -TypeName psobject
$mysqlserverresources = New-Object -TypeName psobject
$mysqlfwruleresources = New-Object -TypeName psobject
$postgresqlserverresources = New-Object -TypeName psobject
$postgresqlfwruleresources = New-Object -TypeName psobject
$elasticpoolresources = New-Object -TypeName psobject
$databaseresources = New-Object -TypeName psobject
$redisresources = New-Object -TypeName psobject
$cdnprofileresources = New-Object -TypeName psobject
$tmprofileresources = New-Object -TypeName psobject
$rgs = @{}
$avsets = @{}

# Get data from Build File
$build = Get-Content $buildfile | ConvertFrom-Json
$buildby = $build.ConfigurationItems.Build.Engineer
$builddate = $build.ConfigurationItems.Build.Date
$buildticket = $build.ConfigurationItems.Build.Ticket

foreach($buildenv in $build.ConfigurationItems.Environment){
    $environment = $buildenv.name

    $tags = @{
        'Environment' = $environment
        'BuildBy' = $buildby
        'BuildDate' = $builddate
        'BuildTicket' = $buildticket
    }

    # Create OMS Workspace
    if($buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name){
        $oms = Get-Content "$templatesdirpath\OperationalInsights\oms.json" | ConvertFrom-Json
        $oms.name = $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name
        $oms.location = $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.Location
        $oms.resource_group_name = '${azurerm_resource_group.' + $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.ResourceGroupName + '.name}'
        $oms.sku = $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.tier
        $oms.tags = $tags
        $oms.tags.Add('Group','Rackspace')
        $omsresources | Add-Member -MemberType NoteProperty -Name $oms.name -Value $oms
        if(-not $rgs.ContainsKey($buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.ResourceGroupName)){$rgs.Add($buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.ResourceGroupName,$buildenv.region)}

        # Create OMS Automation Account
        $omsaa = Get-Content "$templatesdirpath\Automation\automationAccounts\automation-account.json" | ConvertFrom-Json
        $omsaa.name = if($oms.name -like 'rax-*-oms'){$oms.name + '-aa'}else{'rax-' + ($oms.name -split '-')[0] + '-aa'}
        $omsaa.location = if(($oms.location -match 'eastus') -or ($oms.location -match 'East US')){'eastus2'}else{$oms.location}
        $omsaa.resource_group_name = $oms.resource_group_name
        $omsaa.tags = $tags
        $aaresources | Add-Member -MemberType NoteProperty -Name $omsaa.name -Value $omsaa

        # Link Automation Account to OMS
        $omslinkedservice = Get-Content "$templatesdirpath\OperationalInsights\omslinkedservice.json" | ConvertFrom-Json
        $omslinkedservice.resource_group_name = $oms.resource_group_name
        $omslinkedservice.workspace_name = '${azurerm_log_analytics_workspace.' + $oms.name + '.name}'
        $omslinkedservice.resource_id = '${azurerm_automation_account.' + $omsaa.name + '.id}'
        $omslinkedserviceresources | Add-Member -MemberType NoteProperty -Name ('LinkAAto-' + $oms.name) -Value $omslinkedservice

        # Add Update Management Solution
        $omsupdatemgmt = Get-Content "$templatesdirpath\OperationalInsights\omssolution.json" | ConvertFrom-Json
        $omsupdatemgmt.solution_name = 'Updates'
        $omsupdatemgmt.location = $oms.location
        $omsupdatemgmt.resource_group_name = $oms.resource_group_name
        $omsupdatemgmt.workspace_name = '${azurerm_log_analytics_workspace.' + $oms.name + '.name}'
        $omsupdatemgmt.workspace_resource_id = '${azurerm_log_analytics_workspace.' + $oms.name + '.id}'
        $omssolutionsresources | Add-Member -MemberType NoteProperty -Name 'UpdateMgmtSolution' -Value $omsupdatemgmt
    }

    # Create Automation Account
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.name){
        if($buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.name -notlike $omsaa.name){
            $aa = Get-Content "$templatesdirpath\Automation\automationAccounts\automation-account.json" | ConvertFrom-Json
            $aa.name = $buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.name
            $aa.location = $buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.location
            $aa.resource_group_name = '${azurerm_resource_group.' + $buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.ResourceGroupName + '.name}'
            if($buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.Sku){$aa.sku_name = $buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.Sku}
            $aa.tags = $tags
            $aaresources | Add-Member -MemberType NoteProperty -Name $aa.name -Value $aa
            if(-not $rgs.ContainsKey($buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.ResourceGroupName)){$rgs.Add($buildenv.Provider.AzureResourceManager.'Microsoft.Automation'.automationAccounts.ResourceGroupName,$aa.location)}
        }
    }

    # Create Recovery Services Vault
    if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.name){
        $rsv = Get-Content "$templatesdirpath\RecoveryServices\vaults\rsv.json" | ConvertFrom-Json
        $rsv.name = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.name
        $rsv.location = $buildenv.region
        $rsv.resource_group_name = '${azurerm_resource_group.' + $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.ResourceGroupName + '.name}'
        $rsv.tags = $tags
        # Execute Script Change RSV to Local Redundancy
        $localexec = Get-Content "$templatesdirpath\RackspaceUtilities\localexec.json" | ConvertFrom-Json
        $localexec.'local-exec'.command = 'az login --service-principal --username ' + '${var.client_id}' + ' --password ' + '${var.client_secret}' + ' --tenant ' + '${var.tenant_id}' + '; az backup vault backup-properties set --backup-storage-redundancy LocallyRedundant --name ' + ('${azurerm_recovery_services_vault.' + $rsv.name + '.name}') + ' --resource-group ' + $rsv.resource_group_name + ' --subscription ' + '${var.subscription_id}'
        $localexec.'local-exec'.interpreter = @('Powershell','-Command')
        $rsv | Add-Member -MemberType NoteProperty -Name 'provisioner' -Value $localexec

        $rsvresources | Add-Member -MemberType NoteProperty -Name $rsv.name -Value $rsv
        if(-not $rgs.ContainsKey($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.ResourceGroupName)){$rgs.Add($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.ResourceGroupName,$rsv.location)}

        # Create Protection Policy
        if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.policyName){
            $protectionpolicy = Get-Content "$templatesdirpath\RecoveryServices\vaults\protectionpolicy.json" | ConvertFrom-Json
            $protectionpolicy.name = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.policyName
            $protectionpolicy.resource_group_name = $rsv.resource_group_name
            $protectionpolicy.recovery_vault_name = '${azurerm_recovery_services_vault.' + $rsv.name + '.name}'
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.TimeZone){$protectionpolicy.timezone = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.TimeZone}
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.dailyRetentionDurationCount){$protectionpolicy.retention_daily.count = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.dailyRetentionDurationCount}
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.weeklyRetentionDurationCount){$protectionpolicy.retention_weekly.count = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.weeklyRetentionDurationCount}
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.daysOfTheWeek){$protectionpolicy.retention_weekly.weekdays = @($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.daysOfTheWeek)}
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.scheduleRunTimes){$protectionpolicy.backup.time = $buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.scheduleRunTimes}
            $vmprotectionpolicyresources | Add-Member -MemberType NoteProperty -Name ($rsv.name + '_' + $protectionpolicy.name) -Value $protectionpolicy
        }
    
    }

    # Create Network Security Groups
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.networkSecurityGroups.name){
        foreach($buildnsg in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.networkSecurityGroups){
            switch ($buildnsg.DeploymentType){
                'Bastion' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\bast-nsg.json" | ConvertFrom-Json
                }
                'ApplicationGateway' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\agw-nsg.json" | ConvertFrom-Json
                }
                'DomainController' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\ad-nsg.json" | ConvertFrom-Json
                }
                'SitecoreCMS' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\agw-nsg.json" | ConvertFrom-Json
                }
                'SitecoreSOLR' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\sitecoreSOLR-nsg.json" | ConvertFrom-Json
                }
                'AlertLogic' {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\alertlogic-nsg.json" | ConvertFrom-Json
                }
                default {
                    $nsg = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\default-nsg.json" | ConvertFrom-Json
                }
            }
            $nsg.name = $buildnsg.name
            $nsg.location = $buildenv.region
            $nsg.resource_group_name = '${azurerm_resource_group.' + $buildnsg.ResourceGroupName + '.name}'
            $nsg.tags = $tags
            foreach($existingrule in $nsg.security_rule){
                switch($existingrule.source_address_prefix){
                    'LOCALCIDR' {
                        $existingrule.source_address_prefix = $buildnsg.DestinationPrefix
                    }
                    'BASTCIDR' {
                        $existingrule.source_address_prefix = $buildnsg.BastionPrefix
                    }
                }
                switch($existingrule.destination_address_prefix){
                    'LOCALCIDR' {
                        $existingrule.destination_address_prefix = $buildnsg.DestinationPrefix
                    }
                }
            }
            foreach($customrule in $buildnsg.SecurityRules){
                $rule = Get-Content "$templatesdirpath\Network\NetworkSecurityGroups\security-rule.json" | ConvertFrom-Json
                $rule.name = $customrule.name
                $rule.priority = $customrule.properties.priority
                if($customrule.properties.direction){$rule.direction = $customrule.properties.direction}
                if($customrule.properties.access){$rule.access = $customrule.properties.access}
                if($customrule.properties.protocol){$rule.protocol = $customrule.properties.protocol}
                if($customrule.properties.sourceportrange){$rule.source_port_range = $customrule.properties.sourceportrange}
                if($customrule.properties.destinationportrange){$rule.destination_port_range = $customrule.properties.destinationportrange}
                $rule.source_address_prefix = $customrule.properties.sourceaddressprefix
                $rule.destination_address_prefix = $customrule.properties.destinationaddressprefix
                $rule.description = $customrule.properties.description
                $nsg.security_rule += $rule
            }

            $nsgresources | Add-Member -MemberType NoteProperty -Name $nsg.name -Value $nsg

            if(-not $rgs.ContainsKey($buildnsg.ResourceGroupName)){$rgs.Add($buildnsg.ResourceGroupName,$nsg.location)}
        }
    }

    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworks.name){
        foreach($buildvnet in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworks){
            # Create VNet
            $vnet = Get-Content "$templatesdirpath\Network\VirtualNetwork\vnet.json" | ConvertFrom-Json
            $vnet.name = $buildvnet.name
            $vnet.location = $buildenv.region
            $vnet.resource_group_name = '${azurerm_resource_group.' + $buildvnet.ResourceGroupName + '.name}'
            $vnet.address_space = @($buildvnet.addressSpace)
            $vnet.tags = $tags

            foreach($subnet in $buildvnet.subnets){
                # Create Subnet
                $sub = Get-Content "$templatesdirpath\Network\VirtualNetwork\subnet.json" | ConvertFrom-Json
                $sub.name = $subnet.name
                $sub.address_prefix = $subnet.properties.addressPrefix
                if($subnet.name -notlike "GatewaySubnet"){
                    $checknsg = $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.networkSecurityGroups | Where-Object{ ($_.DestinationPrefix -match $subnet.properties.addressPrefix) -and ($_.Network.VirtualNetworkName -match $buildvnet.name) -and ($_.Network.ResourceGroupName -match $buildvnet.ResourceGroupName)}
                    $sub.security_group = '${azurerm_network_security_group.' + $checknsg.name + '.id}'
                }
                $vnet.subnet += $sub

                # Create Subnet DataSource
                $subds = Get-Content "$templatesdirpath\Network\VirtualNetwork\subnet-datasource.json" | ConvertFrom-Json
                $subds.name = $subnet.name
                $subds.virtual_network_name = '${azurerm_virtual_network.' + $vnet.name + '.name}'
                $subds.resource_group_name = $vnet.resource_group_name
                $subnetdatasources | Add-Member -MemberType NoteProperty -Name ('ds_' + $vnet.name + '_' + $subnet.name) -Value $subds
            }

            $vnetresources | Add-Member -MemberType NoteProperty -Name $vnet.name -Value $vnet

            if(-not $rgs.ContainsKey($buildvnet.ResourceGroupName)){$rgs.Add($buildvnet.ResourceGroupName,$vnet.location)}
        }
    }

    if($buildenv.Provider.AzureResourceManager.'Microsoft.Compute'.virtualMachines.name){
        if(-not $saresources.($buildenv.region + '-vmdiagsa')){
            # Generate Random ID for Diagnostics Storage Account
            $rid = Get-Content "$templatesdirpath\RackspaceUtilities\random-id.json" | ConvertFrom-Json
            $ridresources | Add-Member -MemberType NoteProperty -Name ($buildenv.region + '-randomID') -Value $rid

            # Create VM Diagnostics Storage Account
            $diagsa = Get-Content "$templatesdirpath\Storage\storage-account.json" | ConvertFrom-Json
            $vmreference = Get-Content "$templatesdirpath\Compute\virtualMachines\vmreference.json" | ConvertFrom-Json
            $diagsa.name = $vmreference.regions.($buildenv.region).abbreviation + 'vmdiagsa${random_id.' + $buildenv.region + '-randomID.hex}'
            $diagsa.location = $buildenv.region
            $diagsa.resource_group_name = '${azurerm_resource_group.' + ($buildenv.Provider.AzureResourceManager.'Microsoft.Compute'.virtualMachines | Select-Object -First 1).Network.ResourceGroupName + '.name}'
            $diagsa.account_tier = 'Standard'
            $diagsa.account_replication_type = 'LRS'
            $diagsa.tags = $tags
            $saresources | Add-Member -MemberType NoteProperty -Name ($buildenv.region + '-vmdiagsa') -Value $diagsa
        }
        # Create VMs
        foreach($buildvm in $buildenv.Provider.AzureResourceManager.'Microsoft.Compute'.virtualMachines){
            $vm = Get-Content "$templatesdirpath\Compute\virtualMachines\vm.json" | ConvertFrom-Json
            $vmreference = Get-Content "$templatesdirpath\Compute\virtualMachines\vmreference.json" | ConvertFrom-Json
            $vm.name = $buildvm.name
            $vm.location = $buildenv.region
            $vm.resource_group_name = '${azurerm_resource_group.' + $buildvm.ResourceGroupName + '.name}'
            $vm.network_interface_ids = @()
            # Create VM NIC
                $nic = Get-Content "$templatesdirpath\Compute\virtualMachines\nic.json" | ConvertFrom-Json
                $nic.name = $buildvm.Network.name
                $nic.location = $buildenv.region
                $nic.resource_group_name = '${azurerm_resource_group.' + $buildvm.ResourceGroupName + '.name}'
                $nic.ip_configuration.subnet_id = '${data.azurerm_subnet.ds_' + $buildvm.Network.VirtualNetworkName + '_' + $buildvm.Network.SubnetName + '.id}'
                $nic.tags = $tags
                $nicresources | Add-Member -MemberType NoteProperty -Name $nic.name -Value $nic
                $vm.network_interface_ids += ('${azurerm_network_interface.' + $nic.name + '.id}')
            $vm.availability_set_id = '${azurerm_availability_set.' + $buildvm.AvailabilitySetName + '.id}'
            $vm.vm_size = 'Standard_' + $buildvm.Size
            $vm.storage_image_reference.publisher = $vmreference.Image.($buildvm.operatingSystem).imagepublisher
            $vm.storage_image_reference.offer = $vmreference.Image.($buildvm.operatingSystem).imageoffer
            $vm.storage_image_reference.sku = $vmreference.Image.($buildvm.operatingSystem).imagesku
            $vm.storage_image_reference.version = $vmreference.Image.($buildvm.operatingSystem).version
            $vm.storage_os_disk.name = $buildvm.name + '_osdisk'
            if($buildvm.Size -like '*s*'){
                $vm.storage_os_disk.managed_disk_type = 'Premium_LRS'
            }
            else{
                $vm.storage_os_disk.managed_disk_type = 'Standard_LRS'
            }
            $vm.os_profile.computer_name = $vm.name
            $vm.os_profile.admin_username = $vm.name.ToLower() + '-adm'
            if($buildvm.operatingSystem -like '*Linux*'){
                $linuxConfig = @{
                    "disable_password_authentication" = "false"
                }
                $vm | Add-Member -MemberType NoteProperty -Name 'os_profile_linux_config' -Value $linuxConfig
            }
            else{
                $windowsConfig = @{
                    "provision_vm_agent" = "true"
                    "timezone" = $vmreference.regions.($buildenv.region).timezone
                    "enable_automatic_upgrades" = "false"
                }
                $vm | Add-Member -MemberType NoteProperty -Name 'os_profile_windows_config' -Value $windowsConfig
            }
            if($buildvm.operatingSystem -like '*AlertLogic*'){
                $alplan = @{
                    "name" = "20215000100-tmpbyol"
                    "publisher" = "alertlogic"
                    "product" = "alert-logic-tm"
                }
                $vm | Add-Member -MemberType NoteProperty -Name 'plan' -Value $alplan
            }
            $vm.boot_diagnostics.storage_uri = '${azurerm_storage_account.' + $buildenv.region + '-vmdiagsa.primary_blob_endpoint}'
            $vm.tags = $tags
            foreach($datadisk in $buildvm.dataDisks){
                $dd = Get-Content "$templatesdirpath\Compute\virtualMachines\datadisk.json" | ConvertFrom-Json
                $dd.name = $datadisk.name
                $dd.create_option = 'Empty'
                if($datadisk.caching){$dd.caching = $datadisk.caching}
                $dd.lun = $datadisk.lun
                $dd.managed_disk_type = $vmreference.Disk.($datadisk.size).sku
                $dd.disk_size_gb = $vmreference.Disk.($datadisk.size).size
                $vm.storage_data_disk += $dd
            }
            
            # Disable Windows Firewall and UAC
            if($buildvm.operatingSystem -like '*Windows*'){
                $vmlocalexec = Get-Content "$templatesdirpath\RackspaceUtilities\localexec.json" | ConvertFrom-Json
                $vmlocalexec.'local-exec'.command = 'az login --service-principal --username ' + '${var.client_id}' + ' --password ' + '${var.client_secret}' + ' --tenant ' + '${var.tenant_id}' + '; az vm run-command invoke --command-id RunPowerShellScript --name ' + $vm.name + ' --resource-group ' + $vm.resource_group_name + " --scripts 'Set-NetFirewallProfile -All -Enabled False; New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force'"
                $vmlocalexec.'local-exec'.interpreter = @('Powershell','-Command')
                $vm | Add-Member -MemberType NoteProperty -Name 'provisioner' -Value $vmlocalexec
            }

            $vmresources | Add-Member -MemberType NoteProperty -Name $vm.name -Value $vm

            if(-not $rgs.ContainsKey($buildvm.ResourceGroupName)){$rgs.Add($buildvm.ResourceGroupName,$vm.location)}
            if(-not $avsets.ContainsKey($buildvm.availabilitySetName)){$avsets.Add($buildvm.availabilitySetName,$vm.location)}

            # Add BGInfo Extension
            if($buildvm.operatingSystem -like '*Windows*'){
                $bginfoext = Get-Content "$templatesdirpath\Compute\virtualMachines\extensions\bginfo-extension.json" | ConvertFrom-Json
                $bginfoext.location = $vm.location
                $bginfoext.resource_group_name = $vm.resource_group_name
                $bginfoext.virtual_machine_name = '${azurerm_virtual_machine.' + $vm.name + '.name}'
                $vmextresources | Add-Member -MemberType NoteProperty -Name ($vm.name + '_bginfo_ext') -Value $bginfoext
            }

            # Add OMS Extension
            if($buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name){
                $omsext = Get-Content "$templatesdirpath\Compute\virtualMachines\extensions\oms-extension.json" | ConvertFrom-Json
                $omsext.location = $vm.location
                $omsext.resource_group_name = $vm.resource_group_name
                $omsext.virtual_machine_name = '${azurerm_virtual_machine.' + $vm.name + '.name}'
                if($buildvm.operatingSystem -like '*Linux*'){
                    $omsext.type = 'OmsAgentForLinux'
                    $omsext.type_handler_version = '1.7'
                }
                else{
                    $omsext.type = 'MicrosoftMonitoringAgent'
                    $omsext.type_handler_version = '1.0'
                }
                $workspaceidref = '${azurerm_log_analytics_workspace.' + $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name + '.workspace_id}'
                $workspacekeyref = '${azurerm_log_analytics_workspace.' + $buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name + '.primary_shared_key}'
                $omsext.settings = `
@"
{
   "workspaceId" : "$workspaceidref"
}
"@
                $omsext.protected_settings = `
@"
{
   "workspacekey" : "$workspacekeyref"
}
"@

                $vmextresources | Add-Member -MemberType NoteProperty -Name ($vm.name + '_oms_ext') -Value $omsext
            }

            # Add VM to RSV Backups
            if($buildenv.Provider.AzureResourceManager.'Microsoft.RecoveryServices'.vaults.policyName){
                $vmbackup = Get-Content "$templatesdirpath\RecoveryServices\vaults\protectedvm.json" | ConvertFrom-Json
                $vmbackup.resource_group_name = $rsv.resource_group_name
                $vmbackup.recovery_vault_name = '${azurerm_recovery_services_vault.' + $rsv.name + '.name}'
                $vmbackup.source_vm_id = '${azurerm_virtual_machine.' + $vm.name + '.id}'
                $vmbackup.backup_policy_id = '${azurerm_recovery_services_protection_policy_vm.' + $rsv.name + '_' + $protectionpolicy.name + '.id}'
                $vmbackupresources | Add-Member -MemberType NoteProperty -Name ($vm.name + '_rsv_backup') -Value $vmbackup
            }

        }

        # Schedule Initial VM Update Deployment
        if($buildenv.Provider.AzureResourceManager.'Microsoft.OperationalInsights'.workspaces.name){
            if(-not $armdeployresources.'ScheduleInitialVMUpdates'){
                $armdeploy = Get-Content "$templatesdirpath\RackspaceUtilities\armdeployment.json" | ConvertFrom-Json
                $initialupdates = Get-Content "$templatesdirpath\Automation\automationAccounts\scheduleinitialupdates.json"
                $armdeploy.name = 'ScheduleInitialVMUpdates'
                $armdeploy.resource_group_name = $omsaa.resource_group_name
                $armdeploy.deployment_mode = 'Incremental'
                $armdeploy.template_body = `
@"
$initialupdates
"@
                $armdeploy.parameters = @{
                    'automationAccountName' = '${azurerm_automation_account.' + $omsaa.name + '.name}'
                    'startTime' = ((get-date).AddHours(2) | get-date -Format s)
                }
                $armdeployresources | Add-Member -MemberType NoteProperty -Name 'ScheduleInitialVMUpdates' -Value $armdeploy
            }
        }
    }

    # Create Load Balancers. Only currently supports Basic Load Balancers with one IP configuration (Terraform Limitation)
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.loadBalancers.name){
        foreach($buildlb in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.loadBalancers){
            switch($buildlb.sku){
                'Basic' {
                    $lb = Get-Content "$templatesdirpath\Network\loadBalancers\loadbalancer.json" | ConvertFrom-Json
                    $lb.name = $buildlb.name
                    $lb.location = $buildenv.region
                    $lb.resource_group_name = '${azurerm_resource_group.' + $buildlb.ResourceGroupName + '.name}'
                    $lb.tags = $tags
                    $lb.sku = $buildlb.sku
                    switch($buildlb.ExternalLoadBalancer){
                        $false {
                            # Create frontend for Internal LB Can only currently create one frontend config with Terraform so ignore any but the first
                            $lb.frontend_ip_configuration.name = $buildlb.loadBalancingRules.FrontendIpConfigurationName | Select-Object -First 1
                            $lb.frontend_ip_configuration | Add-Member -MemberType NoteProperty -Name 'subnet_id' -Value ('${data.azurerm_subnet.ds_' + $buildlb.Network.VirtualNetworkName + '_' + $buildlb.Network.SubnetName + '.id}')
                            switch($buildlb.loadBalancingRules.privateIPAllocationMethod | Select-Object -First 1){
                                'Static' {
                                    $lb.frontend_ip_configuration | Add-Member -MemberType NoteProperty -Name 'private_ip_address_allocation' -Value 'Static'
                                    $lb.frontend_ip_configuration | Add-Member -MemberType NoteProperty -Name 'private_ip_address' -Value ($buildlb.loadBalancingRules.privateIPAddress | Select-Object -First 1)
                                }
                                default {
                                    $lb.frontend_ip_configuration | Add-Member -MemberType NoteProperty -Name 'private_ip_address_allocation' -Value 'Dynamic'
                                }
                            }
                        }
                        $true {
                            # Create frontend for External LB. Can only currently create one frontend config with Terraform so ignore any but the first
                            $lb.frontend_ip_configuration.name = $buildlb.loadBalancingRules.FrontendIpConfigurationName | Select-Object -First 1
                            
                            # Create Load Balancer Public IP
                            $lbpip = Get-Content "$templatesdirpath\Network\PublicIPAddresses\PublicIPAddress.json" | ConvertFrom-Json
                            $lbpip.name = $lb.name + '-pip'
                            $lbpip.location = $buildenv.region
                            $lbpip.resource_group_name = $lb.resource_group_name
                            $lbpip.allocation_method = $buildlb.publicIPAllocationMethod

                            $pipresources | Add-Member -MemberType NoteProperty -Name $lbpip.name -Value $lbpip

                            $lb.frontend_ip_configuration | Add-Member -MemberType NoteProperty -Name 'public_ip_address_id' -Value ('${azurerm_public_ip.' + $lbpip.name + '.id}')
                        }
                    }

                    # Create Backend Pool
                    $bepool = @{
                        'name' = 'bepool'
                        'resource_group_name' = $lb.resource_group_name
                        'loadbalancer_id' = '${azurerm_lb.' + $lb.name + '.id}'
                    }

                    $lbbepoolresources | Add-Member -MemberType NoteProperty -Name ($lb.name + '-bepool') -Value $bepool

                    # Create Load Balancing Rules. Can only currently create one frontend config with Terraform so only rules for first config
                    $firstFeLbrs = $buildlb.loadBalancingRules | Where-Object{$_.FrontendIpConfigurationName -match $lb.frontend_ip_configuration.name}
                    foreach($buildlbr in $firstFeLbrs){
                        if(-not ($lbproberesources.psobject.properties.name -contains ('probe-' + $buildlbr.backendPort))){
                            $probe = @{
                                'name' = 'probe-' + $buildlbr.backendPort
                                'resource_group_name' = $lb.resource_group_name
                                'loadbalancer_id' = '${azurerm_lb.' + $lb.name + '.id}'
                                'port' = $buildlbr.backendPort
                            }

                            $lbproberesources | Add-Member -MemberType NoteProperty -Name $probe.name -Value $probe
                        }
                        $lbr = Get-Content "$templatesdirpath\Network\loadBalancers\lbrule.json" | ConvertFrom-Json
                        $lbr.name = 'lbr-fe' + $buildlbr.frontendPort + '-be' + $buildlbr.backendPort
                        $lbr.resource_group_name = $lb.resource_group_name
                        $lbr.loadbalancer_id = '${azurerm_lb.' + $lb.name + '.id}'
                        $lbr.frontend_ip_configuration_name = $buildlbr.FrontendIpConfigurationName
                        $lbr.protocol = 'Tcp'
                        $lbr.frontend_port = $buildlbr.frontendPort
                        $lbr.backend_port = $buildlbr.backendPort
                        $lbr.backend_address_pool_id = '${azurerm_lb_backend_address_pool.' + $lb.name + '-bepool.id}'
                        $lbr.probe_id = '${azurerm_lb_probe.probe-' + $buildlbr.backendPort + '.id}'
                        if($buildlbr.enableFloatingIP){ $lbr.enable_floating_ip = $buildlbr.enableFloatingIP }
                        if($buildlbr.idleTimeoutInMinutes){ $lbr.idle_timeout_in_minutes = $buildlbr.idleTimeoutInMinutes }
                        if($buildlbr.loadDistribution){ $lbr.load_distribution = $buildlbr.loadDistribution }

                        $lbruleresources | Add-Member -MemberType NoteProperty -Name ($lb.name + '-' + $lbr.name) -Value $lbr
                    }

                    $lbresources | Add-Member -MemberType NoteProperty -Name $lb.name -Value $lb

                    if(-not $rgs.ContainsKey($buildlb.ResourceGroupName)){$rgs.Add($buildlb.ResourceGroupName,$lb.location)}
                }
            }
        }

    }

    # Create Application Gateways
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.applicationGateways.name){
        foreach($buildappgw in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.applicationGateways){
            $appgw = Get-Content "$templatesdirpath\Network\applicationGateways\applicationGateway.json" | ConvertFrom-Json
            $appgw.name = $buildappgw.name
            $appgw.location = $buildenv.region
            $appgw.resource_group_name = '${azurerm_resource_group.' + $buildappgw.ResourceGroupName + '.name}'
            $appgw.tags = $tags
            if(($buildappgw.Tier -like "Standard_V2") -or ($buildappgw.Tier -like "WAF_V2")){
                $appgw.sku.name = $buildappgw.Tier
            }
            else{
                $appgw.sku.name = $buildappgw.Tier + '_' + $buildappgw.Size
            }
            $appgw.sku.tier = $buildappgw.Tier
            $appgw.sku.capacity = $buildappgw.Instances
            $appgw.gateway_ip_configuration.subnet_id = '${data.azurerm_subnet.ds_' + $buildappgw.Network.VirtualNetworkName + '_' + $buildappgw.Network.SubnetName + '.id}'
            
            # Create AppGW Public IP
            $appgwpip = Get-Content "$templatesdirpath\Network\PublicIPAddresses\PublicIPAddress.json" | ConvertFrom-Json
            $appgwpip.name = $appgw.name + '-pip'
            $appgwpip.location = $buildenv.region
            $appgwpip.resource_group_name = $appgw.resource_group_name
            if(($buildappgw.Tier -like "Standard_V2") -or ($buildappgw.Tier -like "WAF_V2")){
                $appgwpip.allocation_method = "Static"
                $appgwpip.sku = "Standard"
            }
            else{
                $appgwpip.allocation_method = "Dynamic"
                $appgwpip.sku = "Basic"
            }

            $pipresources | Add-Member -MemberType NoteProperty -Name $appgwpip.name -Value $appgwpip

            $appgw.frontend_ip_configuration.public_ip_address_id = '${azurerm_public_ip.' + $appgwpip.name + '.id}'

            $appgw.frontend_port += @{
                    "name" = 'feport-http'
                    "port" = 80
            }

            $appgw.frontend_port += @{
                    "name" = 'feport-https'
                    "port" = 443
            }

            $appgw.backend_http_settings += @{
                    "name" = 'beport-http'
                    "port" = 80
                    "protocol" = 'Http'
                    "cookie_based_affinity" = 'Disabled'
                    "request_timeout" = 5
            }

            $appgw.http_listener +=  @{
                "name" = 'lsnr-http'
                "frontend_ip_configuration_name" = 'feconfig'
                "frontend_port_name" = 'feport-http'
                "protocol" = 'Http'
            }

            $appgwrule = $buildappgw.applicationGatewayRules | Select-Object -First 1
            if($appgwrule.sslcertificate){
                $sslcert = @{
                    "name" = 'SSLCert'
                    "data" = $appgwrule.sslCertificate
                    "password" = '${var.sslPassword}'
                }
                $appgw | Add-Member -MemberType NoteProperty -Name 'ssl_certificate' -Value $sslcert
                $appgw.http_listener +=  @{
                    "name" = 'lsnr-https'
                    "frontend_ip_configuration_name" = 'feconfig'
                    "frontend_port_name" = 'feport-https'
                    "protocol" = 'Https'
                    "ssl_certificate_name" = 'SSLCert'
                }
                $redirectconfig = @{
                    'name' = 'http-redirect-config'
                    'redirect_type' = 'Permanent'
                    'target_listener_name' = 'lsnr-https'
                }
                $appgw | Add-Member -MemberType NoteProperty -Name 'redirect_configuration' -Value $redirectconfig
                $appgw.request_routing_rule += @{
                    "name" = 'rule-http-redirect'
                    "rule_type" = 'Basic'
                    "http_listener_name" = 'lsnr-http'
                    "redirect_configuration_name" = 'http-redirect-config'
                }
                $appgw.request_routing_rule += @{
                    "name" = 'rule-https'
                    "rule_type" = 'Basic'
                    "http_listener_name" = 'lsnr-https'
                    "backend_address_pool_name" = 'bepool'
                    "backend_http_settings_name" = 'beport-http'
                }
            }
            else{
                $appgw.request_routing_rule += @{
                    "name" = 'rule-http'
                    "rule_type" = 'Basic'
                    "http_listener_name" = 'lsnr-http'
                    "backend_address_pool_name" = 'bepool'
                    "backend_http_settings_name" = 'beport-http'
                }
            }
            if($buildappgw.Tier -like "*WAF*"){
                $wafconfig = @{
                    'enabled' = $true
                    'firewall_mode' = 'Detection'
                    'rule_set_type' = 'OWASP'
                    'rule_set_version' = '3.0'
                }
                $appgw | Add-Member -MemberType NoteProperty -Name 'waf_configuration' -Value $wafconfig
            }

            # Create Backend Associations with VMs
            # This is looking for VM names in the IPAddress field
            # Also assumes you named your first nic <vmname>-nic with an ipconfig1 and that is what u are binding to...
            foreach($bevm in $appgwrule.backendAddressPool){
                $appgwvmassoc = @{
                    "network_interface_id"    = '${azurerm_network_interface.' + $bevm.IPAddress + '-nic.id}'
                    "ip_configuration_name"   = 'ipconfig1'
                    "backend_address_pool_id" = '${azurerm_application_gateway.' + $appgw.name + '.backend_address_pool.0.id}'
                }
                $appgwvmassocresources | Add-Member -MemberType NoteProperty -Name ($bevm.IPAddress + '-AGW-assoc-' + $rrr.name) -Value $appgwvmassoc
            }

            $appgwresources | Add-Member -MemberType NoteProperty -Name $appgw.name -Value $appgw

            if(-not $rgs.ContainsKey($buildappgw.ResourceGroupName)){$rgs.Add($buildappgw.ResourceGroupName,$appgw.location)}
            }
    }

    # Create VPN Gateways
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworkGateways.name){
        foreach($buildvpngw in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworkGateways){
            $vpngw = Get-Content "$templatesdirpath\Network\virtualNetworkGateways\virtualNetworkGateway.json" | ConvertFrom-Json
            $vpngw.name = $buildvpngw.name
            $vpngw.location = $buildenv.region
            $vpngw.resource_group_name = '${azurerm_resource_group.' + $buildvpngw.ResourceGroupName + '.name}'
            $vpngw.tags = $tags
            $vpngw.type = $buildvpngw.gatewayType
            $vpngw.vpn_type = $buildvpngw.vpnType
            $vpngw.sku = $buildvpngw.sku.name
            $vpngw.ip_configuration.subnet_id = '${data.azurerm_subnet.ds_' + $buildvpngw.Network.VirtualNetworkName + '_' + $buildvpngw.Network.SubnetName + '.id}'
            
            # Create VPNGW Public IP
            $vpngwpip = Get-Content "$templatesdirpath\Network\PublicIPAddresses\PublicIPAddress.json" | ConvertFrom-Json
            $vpngwpip.name = $vpngw.name + '-pip'
            $vpngwpip.location = $buildenv.region
            $vpngwpip.resource_group_name = $vpngw.resource_group_name
            $vpngwpip.allocation_method = "Dynamic"

            $pipresources | Add-Member -MemberType NoteProperty -Name $vpngwpip.name -Value $vpngwpip

            $vpngw.ip_configuration.public_ip_address_id = '${azurerm_public_ip.' + $vpngwpip.name + '.id}'

            $vpngwresources | Add-Member -MemberType NoteProperty -Name $vpngw.name -Value $vpngw

            if(-not $rgs.ContainsKey($buildvpngw.ResourceGroupName)){$rgs.Add($buildvpngw.ResourceGroupName,$vpngw.location)}
        }
    }

    # Create Local Network Gateways
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.localNetworkGateways.name){
        foreach($buildlocalgw in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.localNetworkGateways){
            $localgw = Get-Content "$templatesdirpath\Network\localNetworkGateways\localNetworkGateway.json" | ConvertFrom-Json
            $localgw.name = $buildlocalgw.name
            $localgw.location = $buildenv.region
            $localgw.resource_group_name = '${azurerm_resource_group.' + $buildlocalgw.ResourceGroupName + '.name}'
            $localgw.gateway_address = $buildlocalgw.gatewayIPAddress
            $localgw.address_space = @($buildlocalgw.localNetworkAddressSpace.addressPrefixes)

            $localgwresources | Add-Member -MemberType NoteProperty -Name $localgw.name -Value $localgw

            if(-not $rgs.ContainsKey($buildlocalgw.ResourceGroupName)){$rgs.Add($buildlocalgw.ResourceGroupName,$localgw.location)}
        }
    }
<# # Removing Connections for now until I decide what to do about issues
    # Create VPN Gateway Connections
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.connections.name){
        foreach($buildgwconn in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.connections){
            $gwconn = Get-Content "$templatesdirpath\Network\connections\vpnGatewayConnection.json" | ConvertFrom-Json
            $gwconn.name = $buildgwconn.name
            $gwconn.location = $buildenv.region
            $gwconn.resource_group_name = '${azurerm_resource_group.' + $buildgwconn.ResourceGroupName + '.name}'
            if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworkGateways.name.Contains($buildgwconn.VirtualNetworkGateway1.Name)){
                $gwconn.virtual_network_gateway_id = '${azurerm_virtual_network_gateway.' + $buildgwconn.VirtualNetworkGateway1.Name + '.id}'
            }
            else{
                $gwconn.virtual_network_gateway_id = $buildgwconn.VirtualNetworkGateway1.id
            }
            $gwconn.type = $buildgwconn.connectionType
            if($buildgwconn.connectionType -match 'IPSec'){
                if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.localNetworkGateways.name.Contains($buildgwconn.LocalNetworkGateway2.Name)){
                    $gwconn | Add-Member -MemberType NoteProperty -Name 'local_network_gateway_id' -Value ('${azurerm_local_network_gateway.' + $buildgwconn.LocalNetworkGateway2.Name + '.id}')
                }
                else{
                    $gwconn | Add-Member -MemberType NoteProperty -Name 'local_network_gateway_id' -Value $buildgwconn.LocalNetworkGateway2.id
                }
                $gwconn | Add-Member -MemberType NoteProperty -Name 'shared_key' -Value $buildgwconn.sharedKey
            }
            elseif($buildgwconn.connectionType -match 'Vnet2Vnet'){
                if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.virtualNetworkGateways.name.Contains($buildgwconn.VirtualNetworkGateway2.Name)){
                    $gwconn | Add-Member -MemberType NoteProperty -Name 'peer_virtual_network_gateway_id' -Value ('${azurerm_virtual_network_gateway.' + $buildgwconn.VirtualNetworkGateway2.Name + '.id}')
                }
                else{
                    $gwconn | Add-Member -MemberType NoteProperty -Name 'peer_virtual_network_gateway_id' -Value $buildgwconn.VirtualNetworkGateway2.id
                }
                $gwconn | Add-Member -MemberType NoteProperty -Name 'shared_key' -Value $buildgwconn.sharedKey
            }
            else{
                # Placeholder
            }

            $gwconnresources | Add-Member -MemberType NoteProperty -Name $gwconn.name -Value $gwconn

            if(-not $rgs.ContainsKey($buildgwconn.ResourceGroupName)){$rgs.Add($buildgwconn.ResourceGroupName,$gwconn.location)}
        }
    }
#>
    # Create Azure SQL
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.servers.name){
        # Create SQL Servers
        foreach($buildsqlserver in $buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.servers){
            $sqlserver = Get-Content "$templatesdirpath\SQL\sqlServers\sqlserver.json" | ConvertFrom-Json
            $sqlserver.name = $buildsqlserver.name
            $sqlserver.location = $buildenv.region
            $sqlserver.resource_group_name = '${azurerm_resource_group.' + $buildsqlserver.ResourceGroupName + '.name}'
            if($buildsqlserver.version){ $sqlserver.version = $buildsqlserver.version }
            $sqlserver.administrator_Login = $buildsqlserver.administratorLogin
            $sqlserver.tags = $tags

            $sqlserverresources | Add-Member -MemberType NoteProperty -Name $sqlserver.name -Value $sqlserver

            if(-not $rgs.ContainsKey($buildsqlserver.ResourceGroupName)){$rgs.Add($buildsqlserver.ResourceGroupName,$sqlserver.location)}

            # Add 'Allow access to Azure services'
            $sqlfwrule = Get-Content "$templatesdirpath\SQL\sqlServers\sqlfirewallrule.json" | ConvertFrom-Json
            $sqlfwrule.name = 'AllowAzureServices'
            $sqlfwrule.resource_group_name = '${azurerm_resource_group.' + $buildsqlserver.ResourceGroupName + '.name}'
            $sqlfwrule.server_name = '${azurerm_sql_server.' + $buildsqlserver.name + '.name}'
            $sqlfwrule.start_ip_address = '0.0.0.0'
            $sqlfwrule.end_ip_address = '0.0.0.0'

            $sqlfwruleresources | Add-Member -MemberType NoteProperty -Name ($buildsqlserver.name + '-sqlRule1') -Value $sqlfwrule
        }

        # Create Elastic Pools
        if($buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.elasticpools.name){
            foreach($buildelasticpool in $buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.elasticpools){
                $elasticpool = Get-Content "$templatesdirpath\SQL\ElasticPools\elasticpool.json" | ConvertFrom-Json
                $elasticpool.name = $buildelasticpool.name
                $elasticpool.location = $buildenv.region
                $elasticpool.resource_group_name = '${azurerm_resource_group.' + $buildelasticpool.ResourceGroupName + '.name}'
                $elasticpool.server_name = '${azurerm_sql_server.' + $buildelasticpool.ServerName + '.name}'
                $elasticpool.max_size_gb = $buildelasticpool.maxGB
                $elasticpool.sku.tier = $buildelasticpool.Tier
                if($buildelasticpool.Tier -match "GeneralPurpose"){
                    $elasticpool.sku | Add-Member -MemberType NoteProperty -Name 'family' -Value $buildelasticpool.Family
                    $elasticpool.sku.name = 'GP_' + $buildelasticpool.Family
                    $elasticpool.sku.capacity = $buildelasticpool.vCore
                    $elasticpool.per_database_settings.min_capacity = $buildelasticpool.minCore
                    $elasticpool.per_database_settings.max_capacity = $buildelasticpool.maxCore
                }
                elseif($buildelasticpool.Tier -match "BusinessCritical"){
                    $elasticpool.sku | Add-Member -MemberType NoteProperty -Name 'family' -Value $buildelasticpool.Family
                    $elasticpool.sku.name = 'BC_' + $buildelasticpool.Family
                    $elasticpool.sku.capacity = $buildelasticpool.vCore
                    $elasticpool.per_database_settings.min_capacity = $buildelasticpool.minCore
                    $elasticpool.per_database_settings.max_capacity = $buildelasticpool.maxCore
                }
                else{
                    $elasticpool.sku.name = $buildelasticpool.Tier + 'Pool'
                    $elasticpool.sku.capacity = $buildelasticpool.eDTU
                    $elasticpool.per_database_settings.min_capacity = $buildelasticpool.minDTU
                    $elasticpool.per_database_settings.max_capacity = $buildelasticpool.maxDTU
                }

                $elasticpoolresources | Add-Member -MemberType NoteProperty -Name ($buildelasticpool.ServerName + '_' + $elasticpool.name) -Value $elasticpool

                if(-not $rgs.ContainsKey($buildelasticpool.ResourceGroupName)){$rgs.Add($buildelasticpool.ResourceGroupName,$elasticpool.location)}
            }
        }
        # Create SQL Databases
        if($buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.databases.name){
            foreach($builddatabase in $buildenv.Provider.AzureResourceManager.'Microsoft.Sql'.databases){
                $database = Get-Content "$templatesdirpath\SQL\SQLDatabases\database.json" | ConvertFrom-Json
                $database.name = $builddatabase.name
                $database.location = $buildenv.region
                $database.resource_group_name = '${azurerm_resource_group.' + $builddatabase.ResourceGroupName + '.name}'
                $database.server_name = '${azurerm_sql_server.' + $builddatabase.ServerName + '.name}'
                $database.tags = $tags
                if($builddatabase.ElasticPoolName){
                    $database | Add-Member -MemberType NoteProperty -Name 'elastic_pool_name' -Value ('${azurerm_mssql_elasticpool.' + $database.server_name + '_' + $builddatabase.ElasticPoolName + '.name}')
                }
                elseif($builddatabase.Tier -match "GeneralPurpose"){
                    $database | Add-Member -MemberType NoteProperty -Name 'requested_service_objective_name' -Value ('GP_' + $builddatabase.Family + '_' + $builddatabase.vCore)
                }
                elseif($builddatabase.Tier -match "BusinessCritical"){
                    $database | Add-Member -MemberType NoteProperty -Name 'requested_service_objective_name' -Value ('BC_' + $builddatabase.Family + '_' + $builddatabase.vCore)
                }
                else{
                    $database | Add-Member -MemberType NoteProperty -Name 'edition' -Value $builddatabase.Tier
                    $database | Add-Member -MemberType NoteProperty -Name 'requested_service_objective_name' -Value $builddatabase.Capacity
                }

                $databaseresources | Add-Member -MemberType NoteProperty -Name $database.name -Value $database

                if(-not $rgs.ContainsKey($builddatabase.ResourceGroupName)){$rgs.Add($builddatabase.ResourceGroupName,$database.location)}
            }
        }
    }

    # Create MySQL
    if($buildenv.Provider.AzureResourceManager.'Microsoft.DBforMySql'.servers.name){
        # Create MySQL Servers
        foreach($buildmysqlserver in $buildenv.Provider.AzureResourceManager.'Microsoft.DBforMySql'.servers){
            $mysqlserver = Get-Content "$templatesdirpath\DBforMySQL\servers\mysqlserver.json" | ConvertFrom-Json
            $mysqlserver.name = $buildmysqlserver.name
            $mysqlserver.location = $buildenv.region
            $mysqlserver.resource_group_name = '${azurerm_resource_group.' + $buildmysqlserver.ResourceGroupName + '.name}'
            if($buildmysqlserver.version){$mysqlserver.version = $buildmysqlserver.version}
            if($buildmysqlserver.sslEnforcement){$mysqlserver.ssl_enforcement = $buildmysqlserver.sslEnforcement}
            $mysqlserver.administrator_Login = $buildmysqlserver.administratorLogin
            $mysqlserver.sku.name = $buildmysqlserver.sku
            $mysqlserver.sku.family = ($buildmysqlserver.sku -split '_')[1]
            $mysqlserver.sku.capacity = ($buildmysqlserver.sku -split '_')[2]
            switch((($buildmysqlserver.sku -split '_')[0])){
                'B' {
                    $mysqlserver.sku.tier = 'Basic'
                }
                'GP' {
                    $mysqlserver.sku.tier = 'GeneralPurpose'
                }
                'MO' {
                    $mysqlserver.sku.tier = 'MemoryOptimized'
                }
            }
            if($buildmysqlserver.size){$mysqlserver.storage_profile.storage_mb = $buildmysqlserver.size}
            if($buildmysqlserver.backupRetentionDays){$mysqlserver.storage_profile.backup_retention_days = $buildmysqlserver.backupRetentionDays}
            if($buildmysqlserver.geoRedundantBackup){$mysqlserver.storage_profile.geo_redundant_backup = $buildmysqlserver.geoRedundantBackup}
            $mysqlserver.tags = $tags

            $mysqlserverresources | Add-Member -MemberType NoteProperty -Name $mysqlserver.name -Value $mysqlserver

            if(-not $rgs.ContainsKey($buildmysqlserver.ResourceGroupName)){$rgs.Add($buildmysqlserver.ResourceGroupName,$mysqlserver.location)}

            # Add 'Allow access to Azure services'
            $mysqlfwrule = Get-Content "$templatesdirpath\DBforMySQL\servers\mysqlfirewallrule.json" | ConvertFrom-Json
            $mysqlfwrule.name = 'AllowAzureServices'
            $mysqlfwrule.resource_group_name = '${azurerm_resource_group.' + $buildmysqlserver.ResourceGroupName + '.name}'
            $mysqlfwrule.server_name = '${azurerm_sql_server.' + $buildmysqlserver.name + '.name}'
            $mysqlfwrule.start_ip_address = '0.0.0.0'
            $mysqlfwrule.end_ip_address = '0.0.0.0'

            $mysqlfwruleresources | Add-Member -MemberType NoteProperty -Name ($buildmysqlserver.name + '-sqlRule1') -Value $mysqlfwrule
        }
    }

    # Create PostgreSQL
    if($buildenv.Provider.AzureResourceManager.'Microsoft.DBforPostgreSql'.servers.name){
        # Create PostgreSQL Servers
        foreach($buildpostgresqlserver in $buildenv.Provider.AzureResourceManager.'Microsoft.DBforPostgreSql'.servers){
            $postgresqlserver = Get-Content "$templatesdirpath\DBforPostgreSQL\servers\postgresqlserver.json" | ConvertFrom-Json
            $postgresqlserver.name = $buildpostgresqlserver.name
            $postgresqlserver.location = $buildenv.region
            $postgresqlserver.resource_group_name = '${azurerm_resource_group.' + $buildpostgresqlserver.ResourceGroupName + '.name}'
            if($buildpostgresqlserver.version){$postgresqlserver.version = $buildpostgresqlserver.version}
            if($buildpostgresqlserver.sslEnforcement){$postgresqlserver.ssl_enforcement = $buildpostgresqlserver.sslEnforcement}
            $postgresqlserver.administrator_Login = $buildpostgresqlserver.administratorLogin
            $postgresqlserver.sku.tier = $buildpostgresqlserver.tier
            $postgresqlserver.sku.family = $buildpostgresqlserver.family
            $postgresqlserver.sku.capacity = $buildpostgresqlserver.capacity
            switch($buildpostgresqlserver.tier){
                'Basic' {
                    $postgresqlserver.sku.name = 'B_' + $buildpostgresqlserver.family + '_' + $buildpostgresqlserver.capacity
                }
                'GeneralPurpose' {
                    $postgresqlserver.sku.name = 'GP_' + $buildpostgresqlserver.family + '_' + $buildpostgresqlserver.capacity
                }
                'MemoryOptimized' {
                    $postgresqlserver.sku.name = 'MO_' + $buildpostgresqlserver.family + '_' + $buildpostgresqlserver.capacity
                }
            }
            if($buildpostgresqlserver.storageMB){$postgresqlserver.storage_profile.storage_mb = $buildpostgresqlserver.storageMB}
            if($buildpostgresqlserver.backupRetentionDays){$postgresqlserver.storage_profile.backup_retention_days = $buildpostgresqlserver.backupRetentionDays}
            if($buildpostgresqlserver.geoRedundantBackup){$postgresqlserver.storage_profile.geo_redundant_backup = $buildpostgresqlserver.geoRedundantBackup}
            $postgresqlserver.tags = $tags

            $postgresqlserverresources | Add-Member -MemberType NoteProperty -Name $postgresqlserver.name -Value $postgresqlserver

            if(-not $rgs.ContainsKey($buildpostgresqlserver.ResourceGroupName)){$rgs.Add($buildpostgresqlserver.ResourceGroupName,$postgresqlserver.location)}

            # Add 'Allow access to Azure services'
            $postgresqlfwrule = Get-Content "$templatesdirpath\DBforPostgreSQL\servers\postgresqlfirewallrule.json" | ConvertFrom-Json
            $postgresqlfwrule.name = 'AllowAzureServices'
            $postgresqlfwrule.resource_group_name = '${azurerm_resource_group.' + $buildpostgresqlserver.ResourceGroupName + '.name}'
            $postgresqlfwrule.server_name = '${azurerm_sql_server.' + $buildpostgresqlserver.name + '.name}'
            $postgresqlfwrule.start_ip_address = '0.0.0.0'
            $postgresqlfwrule.end_ip_address = '0.0.0.0'

            $postgresqlfwruleresources | Add-Member -MemberType NoteProperty -Name ($buildpostgresqlserver.name + '-sqlRule1') -Value $postgresqlfwrule
        }
    }

    # Create Redis Cache
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Cache'.Redis.name){
        foreach($buildredis in $buildenv.Provider.AzureResourceManager.'Microsoft.Cache'.Redis){
            $redis = Get-Content "$templatesdirpath\Cache\redis.json" | ConvertFrom-Json
            $redis.name = $buildredis.name
            $redis.location = $buildenv.region
            $redis.resource_group_name = '${azurerm_resource_group.' + $buildredis.ResourceGroupName + '.name}'
            $redis.tags = $tags
            $redis.sku_name = $buildredis.Sku
            switch($buildredis.Sku){
                'Basic' { $redis.family = 'C' }
                'Standard' { $redis.family = 'C' }
                'Premium' { 
                    $redis.family = 'P'
                    if($buildredis.Shards){
                        $redis | Add-Member -MemberType NoteProperty -Name 'shard_count' -Value $buildredis.Shards
                    }
                }
            }
            $redis.capacity = $buildredis.Capacity
            if($buildredis.enableNonSslPort){
                $redis.enable_non_ssl_port = $true
            }

            $redisresources | Add-Member -MemberType NoteProperty -Name $redis.name -Value $redis

            if(-not $rgs.ContainsKey($buildredis.ResourceGroupName)){$rgs.Add($buildredis.ResourceGroupName,$redis.location)}
        }
    }

    # Create Cdn
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Cdn'.profiles.name){
        foreach($buildcdn in $buildenv.Provider.AzureResourceManager.'Microsoft.Cdn'.profiles){
            $cdnprofile = Get-Content "$templatesdirpath\Cdn\profile.json" | ConvertFrom-Json
            $cdnprofile.name = $buildcdn.name
            $cdnprofile.location = $buildenv.region
            $cdnprofile.resource_group_name = '${azurerm_resource_group.' + $buildcdn.ResourceGroupName + '.name}'
            $cdnprofile.sku = $buildcdn.Sku
            $cdnprofile.tags = $tags

            $cdnprofileresources | Add-Member -MemberType NoteProperty -Name $cdnprofile.name -Value $cdnprofile

            if(-not $rgs.ContainsKey($buildcdn.ResourceGroupName)){$rgs.Add($buildcdn.ResourceGroupName,$cdnprofile.location)}
        }
    }

    # Create Traffic Manager
    if($buildenv.Provider.AzureResourceManager.'Microsoft.Network'.trafficmanagerprofiles.name){
        foreach($buildtm in $buildenv.Provider.AzureResourceManager.'Microsoft.Network'.trafficmanagerprofiles){
            $tmprofile = Get-Content "$templatesdirpath\Network\trafficManagerProfiles\trafficManagerProfile.json" | ConvertFrom-Json
            $tmprofile.name = $buildtm.name
            $tmprofile.dns_config.relative_name = $buildtm.name
            $tmprofile.resource_group_name = '${azurerm_resource_group.' + $buildtm.ResourceGroupName + '.name}'
            $tmprofile.traffic_routing_method = $buildtm.RoutingMethod
            $tmprofile.tags = $tags

            $tmprofileresources | Add-Member -MemberType NoteProperty -Name $tmprofile.name -Value $tmprofile

            if(-not $rgs.ContainsKey($buildtm.ResourceGroupName)){$rgs.Add($buildtm.ResourceGroupName,$tmprofile.location)}
        }
    }

}

# Create Resource Groups
$rgkeys = $rgs.Keys
foreach($key in $rgkeys){
    $newrg = Get-Content "$templatesdirpath\ResourceGroup\resource-group.json" | ConvertFrom-Json
    $newrg.name = $key
    $newrg.location = $rgs[$key]
    $rgresources | Add-Member -MemberType NoteProperty -Name $newrg.name -Value $newrg
}

# Create Availability Sets
$avsetkeys = $avsets.Keys
foreach($key in $avsetkeys){
    $newavs = Get-Content "$templatesdirpath\Compute\virtualMachines\avset.json" | ConvertFrom-Json
    $newavs.name = $key
    $newavs.location = $avsets[$key]
    $newavs.resource_group_name = '${azurerm_resource_group.' + (($build.ConfigurationItems.Environment.Provider.AzureResourceManager.'Microsoft.Compute'.virtualMachines | Where-Object{$_.availabilitySetName -like $newavs.name}).ResourceGroupName | Select-Object -First 1) + '.name}'
    $avsetresources | Add-Member -MemberType NoteProperty -Name $newavs.name -Value $newavs
}

# Combine all Resources to Resource Object
if($rgresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_resource_group' -Value $rgresources
}
if($omsresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_log_analytics_workspace' -Value $omsresources
}
if($aaresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_automation_account' -Value $aaresources
}
if($omslinkedserviceresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_log_analytics_linked_service' -Value $omslinkedserviceresources
}
if($omssolutionsresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_log_analytics_solution' -Value $omssolutionsresources
}
if($rsvresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_recovery_services_vault' -Value $rsvresources
}
if($vmprotectionpolicyresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_recovery_services_protection_policy_vm' -Value $vmprotectionpolicyresources
}
if($vnetresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_virtual_network' -Value $vnetresources
}
if($nsgresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_network_security_group' -Value $nsgresources
}
if($ridresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'random_id' -Value $ridresources
}
if($saresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_storage_account' -Value $saresources
}
if($nicresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_network_interface' -Value $nicresources
}
if($vmresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_virtual_machine' -Value $vmresources
}
if($vmextresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_virtual_machine_extension' -Value $vmextresources
}
if($vmbackupresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_recovery_services_protected_vm' -Value $vmbackupresources
}
if($armdeployresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_template_deployment' -Value $armdeployresources
}
if($lbresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_lb' -Value $lbresources
}
if($lbruleresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_lb_rule' -Value $lbruleresources
}
if($lbbepoolresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_lb_backend_address_pool' -Value $lbbepoolresources
}
if($lbproberesources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_lb_probe' -Value $lbproberesources
}
if($pipresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_public_ip' -Value $pipresources
}
if($appgwvmassocresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_network_interface_application_gateway_backend_address_pool_association' -Value $appgwvmassocresources
}
if($appgwresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_application_gateway' -Value $appgwresources
}
if($vpngwresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_virtual_network_gateway' -Value $vpngwresources
}
if($localgwresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_local_network_gateway' -Value $localgwresources
}
if($gwconnresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_virtual_network_gateway_connection' -Value $gwconnresources
}
if($sqlserverresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_sql_server' -Value $sqlserverresources
}
if($sqlfwruleresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_sql_firewall_rule' -Value $sqlfwruleresources
}
if($elasticpoolresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_mssql_elasticpool' -Value $elasticpoolresources
}
if($databaseresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_sql_database' -Value $databaseresources
}
if($mysqlserverresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_mysql_server' -Value $mysqlserverresources
}
if($mysqlfwruleresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_mysql_firewall_rule' -Value $mysqlfwruleresources
}
if($postgresqlserverresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_postgresql_server' -Value $postgresqlserverresources
}
if($postgresqlfwruleresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_postgresql_firewall_rule' -Value $postgresqlfwruleresources
}
if($redisresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_redis_cache' -Value $redisresources
}
if($cdnprofileresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_cdn_profile' -Value $cdnprofileresources
}
if($tmprofileresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_traffic_manager_profile' -Value $tmprofileresources
}
if($avsetresources.psobject.Properties.value){
    $resources | Add-Member -MemberType NoteProperty -Name 'azurerm_availability_set' -Value $avsetresources
}

# Combine all Data Sources to Data Object
if($subnetdatasources.psobject.Properties.value){
    $datasources | Add-Member -MemberType NoteProperty -Name 'azurerm_subnet' -Value $subnetdatasources
}

# Combine all Object for JSON Output
if($resources.psobject.Properties.value){
    $json | Add-Member -MemberType NoteProperty -Name 'resource' -Value $resources
}
if($datasources.psobject.Properties.value){
    $json | Add-Member -MemberType NoteProperty -Name 'data' -Value $datasources
}
if($outputs.psobject.Properties.value){
    $json | Add-Member -MemberType NoteProperty -Name 'output' -Value $outputs
}


# Export JSON Terraform Template and Terraform Variables File to Output Directory
$jsonout = $json | ConvertTo-Json -Depth 10 #| Format-Json
[IO.File]::WriteAllLines("$outputdirpath\main.tf.json", $jsonout)

Copy-Item -Path "$templatesdirpath\variables.tf.json" -Destination "$outputdirpath\variables.tf.json"