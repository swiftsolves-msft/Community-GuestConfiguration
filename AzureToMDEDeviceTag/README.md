The following Guest Configuration artifacts can be used to check for MDE Tag and create one. This can be useful for Device Groups and filtering Azure and Arc connected VMs via Defender for Servers in Defender for Cloud. You may want these Windows Servers with differnt AIRs, Permissions via Tag and Device group as well. Pull down the artifacts and use the following Powershell lines to publish the Guest Configuration as a Azure Policy in yur subscription.

Tags: edr, registry

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

Steps 1 through 4 are completed, details can be [found here](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/7-steps-to-author-develop-and-deploy-custom-recommendations-for/ba-p/3166026 "found here")

#### [Step 5](https://docs.microsoft.com/en-us/azure/governance/policy/how-to/guest-configuration-create-test#validate-the-configuration-package-meets-requirements "Step 5"): Publish custom Guest Configuration package to Azure Blob Storage

In this step you will use another GuestConfiguration cmdlet to upload the .zip package you tested previously to a Azure Blob Storage account – in addition a blob uri will be returned with a sas signature that lasts a few years. This sas based signature will be used when creating the Azure policy and publishing it in the next step. 

```
Publish-GuestConfigurationPackage -Path './AzureToMDEDeviceTag/AzureToMDEDeviceTag.zip' `
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
  -PolicyId 'f2bcb76b-d41b-4be8-bc17-e5814a06ae98' `
  -ContentUri 'https://somestorage.blob.core.windows.net/guestconfiguration/AzureToMDEDeviceTag.zip?sv=2020-08-04&st=2022-02-08T17%3A12%3A03Z&se=2025-02-08T17%3A12%3A03Z&sr=b&sp=rl&sig' `
  -DisplayName 'Azure MDC-MDE Onboarded Windows Server Set MDE Device Tag' `
  -Description 'Registry check and add value for MDE Device tagging to be used to filter, apply permissions, set AIRs via MDE: Device Groups.' `
  -Path './policies' `
  -Platform 'Windows' `
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