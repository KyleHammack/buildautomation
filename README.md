# Terraform Template Repo

Script and Templates for Terraform Automated Build Process.

GenerateTerraform.ps1 can be run against a build.json file that has AzureResourceManager Resources. The script will output a main.tf.json and variables.tf.json that can be used by Terraform to deploy.

An Azure DevOps Build and Release Pipeline has been setup to utilize this process so that you only need to have a build.json file in the root of your git repository and the needed Azure DevOps pipeline variables filled in.

# Requirements and Oddities

- Virtual Machines currently only supports Marketplace Images

- Virtual Machines can be created to an existing VNET, but will only be connected to Log Analytics and enable boot diagnostics if Log Analytics is deployed at the same time.

- Load Balancers only currently supports Basic sku and a single frontend IP Configuration (current Terraform limitation)

- Application Gateway currently only supports HTTP on port 80 or HTTPS on 443 with SSL Offloading (put PFX data in 'sslCertificate' field)

- Application Gateway Backend Address Pool requires you put Server Names in the IpAddress field of your build.json.

- Application Gateway Backend Address Pool also assumes you named your first nic <vmname>-nic and that is what u are binding to...Not the best solution, looking for ways to improve.

- Additional security rules can be added to an NSG's deployment types default rules by specifying an array of SecurityRules.

# Currently Supported Resources

- Resource Groups (Created off of what Resource Group your resources say they are in)
- Log Analytics Workspaces
- Automation Accounts
- Recovery Services Vaults
- Virtual Networks and Subnets
- Network Security Groups
- Virtual Machines
- Load Balancers (Basic only. Only one frontend IP Configuration)
- Application Gateways
- Virtual Network Gateways
- Local Network Gateways
- Azure SQL Servers
- Azure SQL Elastic Pools
- Azure SQL Databases
- Redis Cache
- CDN
- Traffic Manager

# Script Usage Example

& "C:\git\buildautomation\BuildAutomation\GenerateTerraform.ps1" -buildfile "C:\Users\kyle2880\Desktop\test\build.json" -outputdirpath "C:\Users\kyle2880\Desktop\test" -templatesdirpath "C:\git\buildautomation\BuildAutomation\Templates"

# Azure DevOps Pipelines

Build and Release pipelines have been created to utilize this script. The pipelines can be imported into your new Project from BuildAutomation\Definitions.

- Your GIT repository only needs your build.json file in the root of the repository. Don't put any passwords in your build.json file, these should be entered as secure variables in the pipeline.

- Add your Build Artifact with the Alias 'Build' and mark it as Primary

- Update pipeline variables for subscription info and credentials

- Update all Environments with proper Agent Pool and all Azure Tasks with proper Azure Subscription connection