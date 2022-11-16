The following Guest Configuration artifacts can be used to check for the absence of Sophos AV running a Windows Server. If not found then download the Sophos AV from a your Sophos Central URL, then install Sophos AV. Because this uses a Sophos Central URL unquie to your tenant you must use Sophos.ps1 and edit and replace the URL and Compile through all the steps. Use the following Powershell lines to compile and publish the Guest Configuration as a Azure Policy in yur subscription.

To obtain the Sophos Agent URL to download the SophosSetup.exe installer, Go to Sophos Central, Protect Devices, and righ click and copy link on the Windows Installer link

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/sophoscentral.png)

Tags: av, edr, service

PreReqs

Download and Install PowerShell 7.1.3 or higher: 

https://github.com/PowerShell/PowerShell/releases/download/v7.1.3/PowerShell-7.1.3-win-x64.msi 

Using the PowerShell 7 (x64) console, install the following modules: 

```
Install-Module Az 
Install-Module GuestConfiguration 
Install-Module PSDscResources
Import-Module GuestConfiguration
Import-Module PSDscResources
Connect-AzAccount
```

Details can be [found here](https://swiftsolves.substack.com/p/remix-with-a-twist-7-steps-to-author "found here")

#### [Step 1](https://swiftsolves.substack.com/i/74598574/step-test-guest-configuration-policy-in-local-environment "Step 1"): Build Authoring AM | Author DSC

Be sure to modify the URL for the download process for Sophos AV

#### [Step 2](https://learn.microsoft.com/en-us/powershell/dsc/configurations/configurations?view=dsc-1.1#compiling-the-configuration "Step 2"): Compile DSC to create .MOF

```
. .\Sophos.ps1 
Sophos
```

#### [Step 3](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-create#create-a-configuration-package-artifact "Step 3"): Create a Guest Configuration package .ZIP

```
New-GuestConfigurationPackage `
  -Name 'WindowsSophos' `
  -Configuration './Sophos/Sophos.mof' `
  -Type AuditandSet `
  -Force
```

#### [Step 4](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-create-test#validate-the-configuration-package-meets-requirements "Step 4"): Test Guest Configuration Policy in enviroment

```
Start-GuestConfigurationPackageRemediation -Path ./WindowsSophos/WindowsSophos.zip
```


#### [Step 5](https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-test#validate-the-configuration-package-meets-requirements "Step 5"): Publish custom Guest Configuration package to Azure Blob Storage

In this step you will use another GuestConfiguration cmdlet to upload the .zip package you tested previously to a Azure Blob Storage account – in addition a blob uri will be returned with a sas signature that lasts a few years. This sas based signature will be used when creating the Azure policy and publishing it in the next step. 

```
Publish-GuestConfigurationPackage -Path './WindowsSophos/WidowsSophos.zip' `
-ResourceGroupName rgsomestorageDSC -StorageAccountName somestorage | % ContentUri
```

Copy the *sas url signature* 

#### [Step 6](https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-publish#publish-a-configuration-package "Step 6"): Create the custom Azure Policy definition id

In this next step we are going to take the Guest Configuration package in Azure Blob Storage and use it to define a new custom Azure Policy definition. Start with creating a *new guid*. 

```
New-Guid
```

With the new guid and sas blob uri use the following ps cmdlets and replace where necessary. 

```
New-GuestConfigurationPolicy `
  -PolicyId '79436b22-db38-4367-b41d-62a8181faf2c' `
  -ContentUri 'https://somestorage.blob.core.windows.net/guestconfiguration/WindowsSophos.zip?sv=2020-08-04&st=2022-02-08T17%3A12%3A03Z&se=2025-02-08T17%3A12%3A03Z&sr=b&sp=rl&sig' `
  -DisplayName 'Windows Sophos Service.' `
  -Description 'Check for Windows Sophos AV Service. Ensure it is present on VM, if absent then download and install Sophos AV' `
  -Path './policies' `
  -Platform 'Windows' `
  -Mode ApplyAndAutoCorrect `
  -Version 1.0.0 `
  -Verbose
```

To deploy and use:

```
Publish-GuestConfigurationPolicy -Path '.\policies'
```

#### [Step 7](https://docs.microsoft.com/en-us/azure/defender-for-cloud/custom-security-policies?pivots=azure-portal#to-add-a-custom-initiative-to-your-subscription "Step 7"): Using Defender for Cloud create a custom security recommendation

Now that you deployed and created a new custom Azure Policy using Guest Configuration, you can deploy the policy to check Windows VMs on Azure and Azure Arc enabled for the Crowdstrike Falcon Agent software. In effect you have a Azure plane using Azure Policy to check for compliance and in more advanced cases using DSC check and change or install software inside the operating system– recall the PSDscResource module and it’s capabilities. PowerShell/PSDscResources (github.com). You have a outer Azure Policy set and managed a cloud scale your inner servers settings.

The last step is that non compliant states can be sent to Defender for Cloud in the form of Custom security recommendations .

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend.png)

In this last step go to Microsoft Defender for Cloud in the Azure portal and click on the left hand blade environment settings.

Search for your Azure Subscription you deployed the custom Guest Configuration Azure Policy and click on the subscription.

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend2.png)

Click on the Security policy on the left blade and scroll down and click on Add a custom initiative 

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend3.png)

Fill in information, choose the existing category Security Center.

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend4.png)

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend5.png)

Click next until the Policy parameters, uncheck only show parameters that need input or review. You can now extend support to Azure Arc connected servers. By setting these values. 

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend6.png)

Afterwards you add the new custom initiative and Create new.

![](https://github.com/swiftsolves-msft/Community-GuestConfiguration/raw/main/images/MDCreccomend7.png)
