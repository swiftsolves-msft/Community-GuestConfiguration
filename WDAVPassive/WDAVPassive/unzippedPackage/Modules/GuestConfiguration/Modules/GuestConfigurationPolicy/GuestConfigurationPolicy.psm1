#Region './prefix.ps1' 0
Set-StrictMode -Version latest
$ErrorActionPreference = 'Stop'

Import-Module $PSScriptRoot/../DscOperations -Force
#EndRegion './prefix.ps1' 5
#Region './Private/Convert-FileToUnixLineEndings.ps1' 0
function Convert-FileToUnixLineEndings
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $fileContent = Get-Content -Path $FilePath -Raw
    $fileContentWithLinuxLineEndings = $fileContent.Replace("`r`n", "`n")
    $null = Set-Content -Path $FilePath -Value $fileContentWithLinuxLineEndings -Force -NoNewline
    Write-Verbose -Message "Converted the file '$FilePath' to Unix line endings."
}
#EndRegion './Private/Convert-FileToUnixLineEndings.ps1' 16
#Region './Private/Format-Json.ps1' 0
function Format-Json
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Json
    )

    $indent = 0
    $jsonLines = $Json -Split '\n'
    $formattedLines = @()
    $previousLine = ''

    foreach ($line in $jsonLines)
    {
        $skipAddingLine = $false
        if ($line -match '^\s*\}\s*' -or $line -match '^\s*\]\s*')
        {
            # This line contains  ] or }, decrement the indentation level
            $indent--
        }

        $formattedLine = (' ' * $indent * 4) + $line.TrimStart().Replace(':  ', ': ')

        if ($line -match '\s*".*"\s*:\s*\[' -or $line -match '\s*".*"\s*:\s*\{' -or $line -match '^\s*\{\s*' -or $line -match '^\s*\[\s*')
        {
            # This line contains [ or {, increment the indentation level
            $indent++
        }

        if ($previousLine.Trim().EndsWith("{"))
        {
            if ($formattedLine.Trim() -in @("}", "},"))
            {
                $newLine = "$($previousLine.TrimEnd())$($formattedLine.Trim())"
                #Write-Verbose -Message "FOUND SHORTENED LINE: $newLine"
                $formattedLines[($formattedLines.Count - 1)] = $newLine
                $previousLine = $newLine
                $skipAddingLine = $true
            }
        }

        if ($previousLine.Trim().EndsWith("["))
        {
            if ($formattedLine.Trim() -in @("]", "],"))
            {
                $newLine = "$($previousLine.TrimEnd())$($formattedLine.Trim())"
                #Write-Verbose -Message "FOUND SHORTENED LINE: $newLine"
                $formattedLines[($formattedLines.Count - 1)] = $newLine
                $previousLine = $newLine
                $skipAddingLine = $true
            }
        }

        if (-not $skipAddingLine -and -not [String]::IsNullOrWhiteSpace($formattedLine))
        {
            $previousLine = $formattedLine
            $formattedLines += $formattedLine
        }
    }

    $formattedJson = $formattedLines -join "`n"
    return $formattedJson
}
#EndRegion './Private/Format-Json.ps1' 68
#Region './Private/Get-GuestConfigurationAssignmentParameterName.ps1' 0
<#
    .SYNOPSIS
        Retrieves the name of a Guest Configuration Assignment parameter correctly formatted to be passed to the Guest Configuration Assignment.
    .PARAMETER ParameterInfo
        A single hashtable indicating the necessary parameter info from which to retrieve the parameter name.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParameterName -ParameterInfo $currentParameterInfo
#>
function Get-GuestConfigurationAssignmentParameterName
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [Hashtable]
        $ParameterInfo
    )
    $assignmentParameterName = "$($ParameterInfo.MofResourceReference);$($ParameterInfo.MofParameterName)"
    return $assignmentParameterName
}
#EndRegion './Private/Get-GuestConfigurationAssignmentParameterName.ps1' 22
#Region './Private/Get-GuestConfigurationAssignmentParametersExistenceConditionSection.ps1' 0

<#
    .SYNOPSIS
        Retrieves a policy section check for the existence of a Guest Configuration Assignment with the specified parameters.
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParametersExistenceConditionSection -ParameterInfo $parameterInfo
#>
function Get-GuestConfigurationAssignmentParametersExistenceConditionSection
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable[]]
        $ParameterInfo
    )

    $parameterValueConceatenatedStringList = @()
    foreach ($currentParameterInfo in $ParameterInfo)
    {
        $assignmentParameterName = Get-GuestConfigurationAssignmentParameterName -ParameterInfo $currentParameterInfo
        $assignmentParameterStringValue = Get-GuestConfigurationAssignmentParameterStringValue -ParameterInfo $currentParameterInfo
        $currentParameterValueConcatenatedString = "'$assignmentParameterName', '=', $assignmentParameterStringValue"
        $parameterValueConceatenatedStringList += $currentParameterValueConcatenatedString
    }

    $allParameterValueConcantenatedString = $parameterValueConceatenatedStringList -join ", ',', "
    $parameterExistenceConditionEqualsValue = "[base64(concat($allParameterValueConcantenatedString))]"
    $existenceConditionHashtable = [Ordered]@{
        field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/parameterHash'
        equals = $parameterExistenceConditionEqualsValue
    }

    return $existenceConditionHashtable
}
#EndRegion './Private/Get-GuestConfigurationAssignmentParametersExistenceConditionSection.ps1' 40
#Region './Private/Get-GuestConfigurationAssignmentParameterStringValue.ps1' 0
<#
    .SYNOPSIS
        Retrieves the string value of a Guest Configuration Assignment parameter correctly formatted to be passed to the Guest Configuration Assignment as part of the parameter hash.
    .PARAMETER ParameterInfo
        A single hashtable indicating the necessary parameter info from which to retrieve the parameter string value.
    .EXAMPLE
        Get-GuestConfigurationAssignmentParameterStringValue -ParameterInfo $currentParameterInfo
#>
function Get-GuestConfigurationAssignmentParameterStringValue
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [Hashtable]
        $ParameterInfo
    )

    if ($ParameterInfo.ContainsKey('ConfigurationValue'))
    {
        if ($ParameterInfo.ConfigurationValue.StartsWith('[') -and $ParameterInfo.ConfigurationValue.EndsWith(']'))
        {
            $assignmentParameterStringValue = $ParameterInfo.ConfigurationValue.Substring(1, $ParameterInfo.ConfigurationValue.Length - 2)
        }
        else
        {
            $assignmentParameterStringValue = "'$($ParameterInfo.ConfigurationValue)'"
        }
    }
    else
    {
        $assignmentParameterStringValue = "parameters('$($ParameterInfo.ReferenceName)')"
    }

    return $assignmentParameterStringValue
}
#EndRegion './Private/Get-GuestConfigurationAssignmentParameterStringValue.ps1' 38
#Region './Private/Get-GuestConfigurationMofContent.ps1' 0

function Get-GuestConfigurationMofContent
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    Write-Verbose "Parsing Configuration document '$Path'"
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    # Set the profile path for Chef resource
    $resourcesInMofDocument | ForEach-Object {
        if ($_.CimClass.CimClassName -eq 'MSFT_ChefInSpecResource')
        {
            $profilePath = "$Name/Modules/$($_.Name)"
            $item = $_.CimInstanceProperties.Item('GithubPath')
            if ($null -eq $item)
            {
                $item = [Microsoft.Management.Infrastructure.CimProperty]::Create('GithubPath', $profilePath, [Microsoft.Management.Infrastructure.CimFlags]::Property)
                $_.CimInstanceProperties.Add($item)
            }
            else
            {
                $item.Value = $profilePath
            }
        }
    }

    return $resourcesInMofDocument
}
#EndRegion './Private/Get-GuestConfigurationMofContent.ps1' 39
#Region './Private/Get-ParameterDefinition.ps1' 0
<#
    .SYNOPSIS
        Define the parmameters of a policy for Audit or Deploy.
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
#>
function Get-ParameterDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable[]]$ParameterInfo
    )

    $paramDefinition = [Ordered]@{}
    foreach ($item in $ParameterInfo)
    {
        $paramDefinition[$($item.ReferenceName)] = @{
            type = $item.Type
            metadata = [Ordered]@{
                displayName = $item.DisplayName
                description = $item.Description
            }
         }

         if ($item.ContainsKey('AllowedValues'))
         {
            $paramDefinition[$($item.ReferenceName)]['allowedValues'] = $item.AllowedValues
         }

         if ($item.ContainsKey('DefaultValue'))
         {
            $paramDefinition[$($item.ReferenceName)]['defaultValue'] = $item.DefaultValue
         }
    }

    return $paramDefinition
}
#EndRegion './Private/Get-ParameterDefinition.ps1' 40
#Region './Private/Get-ParameterMappingForAINE.ps1' 0


<#
    .SYNOPSIS
        Define the policy parameter mapping to the parameters of the MOF file.
    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
#>
function  Get-ParameterMappingForAINE
{
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param
    (
        [Parameter(Mandatory = $true)]
        [array]
        $ParameterInfo
    )

    $paramMapping = @{}
    foreach ($item in $ParameterInfo)
    {
        $paramMapping[$item.ReferenceName] = ("{0};{1}" -f $item.MofResourceReference, $item.MofParameterName)
    }

    return $paramMapping
}
#EndRegion './Private/Get-ParameterMappingForAINE.ps1' 28
#Region './Private/Get-ParameterMappingForDINE.ps1' 0


<#
    .SYNOPSIS
        Define the policy parameter mapping to the parameters of the MOF file.
        Expected output should follow the following format:
            {
                "name": "[MyFile]createFoobarTestFile;path",
                "value": "[parameters('path')]"
            },
            {
                "name": "[MyFile]createFoobarTestFile;ensure",
                "value": "[parameters('ensure')]"
            },
            {
                "name": "[MyFile]createFoobarTestFile;content",
                "value": "[parameters('content')]"
            }

    .PARAMETER ParameterInfo
        A list of hashtables indicating the necessary info for parameters that need to be passed into this Guest Configuration Assignment.
#>
function Get-ParameterMappingForDINE
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [array]
        $ParameterInfo
    )

    $paramMapping = @()
    foreach ($item in $ParameterInfo)
    {
        $parameterPair = @{
            "name" = ("{0};{1}" -f $item.MofResourceReference, $item.MofParameterName)
            "value" = ("[parameters('{0}')]" -f $item.ReferenceName)
        }
        $paramMapping += $parameterPair
    }

    return $paramMapping
}
#EndRegion './Private/Get-ParameterMappingForDINE.ps1' 45
#Region './Private/New-GuestConfigurationAuditPolicyDefinition.ps1' 0
<#
    .SYNOPSIS
        Creates a new audit policy definition for a guest configuration policy.
#>
function New-GuestConfigurationAuditPolicyDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FileName,

        [Parameter(Mandatory = $true)]
        [String]
        $FolderPath,

        [Parameter(Mandatory = $true)]
        [String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [String]
        $Description,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationName,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationVersion,

        [Parameter(Mandatory = $true)]
        [String]
        $ReferenceId,

        [Parameter()]
        [Hashtable[]]
        $ParameterInfo,

        [Parameter()]
        [String]
        $ContentUri,

        [Parameter()]
        [String]
        $ContentHash,

        [AssignmentType]
        $AssignmentType,

        [Parameter()]
        [bool]
        $UseCertificateValidation = $false,

        [Parameter()]
        [String]
        $Category = 'Guest Configuration',

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [String]
        $Guid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [String]
        $Platform,

        [Parameter()]
        [Hashtable[]]
        $Tag
    )

    $filePath = Join-Path -Path $FolderPath -ChildPath $FileName
    Write-Verbose -Message "Creating Guest Configuration Audit Policy Definition to '$filePath'."

    $auditPolicyGuid = $Guid
    $ParameterMapping = @{ }
    $ParameterDefinitions = @{ }
    $auditPolicyContentHashtable = [Ordered]@{ }

    if ($null -ne $ParameterInfo)
    {
        $ParameterMapping = Get-ParameterMappingForAINE -ParameterInfo $ParameterInfo
        $ParameterDefinitions = Get-ParameterDefinition -ParameterInfo $ParameterInfo
    }

    $ParameterDefinitions['IncludeArcMachines'] += [Ordered]@{
        type          = "string"
        metadata      = [Ordered]@{
            displayName = 'Include Arc connected servers'
            description = 'By selecting this option, you agree to be charged monthly per Arc connected machine.'
        }

        allowedValues = @('True', 'False')
        defaultValue  = 'False'
    }

    $auditPolicyContentHashtable = [Ordered]@{
        properties = [Ordered]@{
            displayName = $DisplayName
            policyType  = 'Custom'
            mode        = 'All'
            description = $Description
            metadata    = [Ordered]@{
                category           = $Category
                guestConfiguration = [Ordered]@{
                    name                   = $ConfigurationName
                    version                = $ConfigurationVersion
                    contentType            = "Custom"
                    contentUri             = $ContentUri
                    contentHash            = $ContentHash
                    configurationParameter = $ParameterMapping
                }
            }
            parameters  = $ParameterDefinitions

        }
        id         = "/providers/Microsoft.Authorization/policyDefinitions/$auditPolicyGuid"
        name       = $auditPolicyGuid
    }


    $policyRuleHashtable = [Ordered]@{
        if   = [Ordered]@{
            anyOf = @(
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            field  = 'type'
                            equals = "Microsoft.Compute/virtualMachines"
                        }
                    )
                },
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            value  = "[parameters('IncludeArcMachines')]"
                            equals = "true"
                        },
                        [Ordered]@{
                            field  = "type"
                            equals = "Microsoft.HybridCompute/machines"
                        }
                    )
                }
            )
        }
        then = [Ordered]@{
            effect  = 'auditIfNotExists'
            details = [Ordered]@{
                type = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
                name = $ConfigurationName
            }
        }
    }

    if ($Platform -ieq 'Windows')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in    = @(
                            'esri',
                            'incredibuild',
                            'MicrosoftDynamicsAX',
                            'MicrosoftSharepoint',
                            'MicrosoftVisualStudio',
                            'MicrosoftWindowsDesktop',
                            'MicrosoftWindowsServerHPCPack'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'MicrosoftWindowsServer'
                            },
                            [Ordered]@{
                                field   = "Microsoft.Compute/imageSKU"
                                notLike = '2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'MicrosoftSQLServer'
                            },
                            [Ordered]@{
                                field   = "Microsoft.Compute/imageOffer"
                                notLike = 'SQL2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{
                                field  = "Microsoft.Compute/imageOffer"
                                equals = 'dsvm-windows'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                in    = @(
                                    'standard-data-science-vm',
                                    'windows-data-science-vm'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'batch'
                            },
                            [Ordered]@{
                                field  = "Microsoft.Compute/imageOffer"
                                equals = 'rendering-windows2016'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like  = 'cis-windows-server-201*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'pivotal'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like  = 'bosh-windows-server*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'cloud-infrastructure-services'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like  = 'ad*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                anyOf = @(
                                    [Ordered]@{
                                        field  = "Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration"
                                        exists = 'true'
                                    },
                                    [Ordered]@{
                                        field = "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType"
                                        like  = 'Windows*'
                                    }
                                )
                            },
                            [Ordered]@{
                                anyOf = @(
                                    [Ordered]@{
                                        field  = "Microsoft.Compute/imageSKU"
                                        exists = 'false'
                                    },
                                    [Ordered]@{
                                        allOf = @(
                                            [Ordered]@{
                                                field   = "Microsoft.Compute/imageSKU"
                                                notLike = '2008*'
                                            },
                                            [Ordered]@{
                                                field   = "Microsoft.Compute/imageOffer"
                                                notLike = 'SQL2008*'
                                            }
                                        )
                                    }
                                )
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "windows*"
            }
        )
    }
    elseif ($Platform -ieq 'Linux')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in    = @(
                            'microsoft-aks',
                            'qubole-inc',
                            'datastax',
                            'couchbase',
                            'scalegrid',
                            'checkpoint',
                            'paloaltonetworks'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'OpenLogic'
                            },
                            [Ordered]@{
                                field = "Microsoft.Compute/imageOffer"
                                like  = 'CentOS*'
                            },
                            [Ordered]@{
                                field   = "Microsoft.Compute/imageSKU"
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = "Microsoft.Compute/imagePublisher"
                                equals = 'Oracle'
                            },
                            [Ordered]@{
                                field  = "Microsoft.Compute/imageOffer"
                                equals = 'Oracle-Linux'
                            },
                            [Ordered]@{
                                field   = "Microsoft.Compute/imageSKU"
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'RHEL',
                                    'RHEL-HA'
                                    'RHEL-SAP',
                                    'RHEL-SAP-APPS',
                                    'RHEL-SAP-HA',
                                    'RHEL-SAP-HANA'
                                )
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'osa',
                                    'rhel-byos'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'cis-centos-7-l1',
                                    'cis-centos-7-v2-1-1-l1'
                                    'cis-centos-8-l1',
                                    'cis-debian-linux-8-l1',
                                    'cis-debian-linux-9-l1',
                                    'cis-nginx-centos-7-v1-1-0-l1',
                                    'cis-oracle-linux-7-v2-0-0-l1',
                                    'cis-oracle-linux-8-l1',
                                    'cis-postgresql-11-centos-linux-7-level-1',
                                    'cis-rhel-7-l2',
                                    'cis-rhel-7-v2-2-0-l1',
                                    'cis-rhel-8-l1',
                                    'cis-suse-linux-12-v2-0-0-l1',
                                    'cis-ubuntu-linux-1604-v1-0-0-l1',
                                    'cis-ubuntu-linux-1804-l1'

                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'credativ'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Debian'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '7*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Suse'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'SLES*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '11*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Canonical'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'UbuntuServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '12*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'linux-data-science-vm-ubuntu',
                                    'azureml'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-centos-os'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-altus-centos-os'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'linux*'
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "linux*"
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'linux*'
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "linux*"
            }
        )
    }
    else
    {
        throw "The specified platform '$Platform' is not currently supported by this script."
    }

    # if there is atleast one tag
    if ($PSBoundParameters.ContainsKey('Tag') -AND $null -ne $Tag)
    {
        # capture existing 'anyOf' section
        $anyOf = $policyRuleHashtable['if']
        # replace with new 'allOf' at top order
        $policyRuleHashtable['if'] = [Ordered]@{
            allOf = @(
            )
        }
        # add tags section under new 'allOf'
        $policyRuleHashtable['if']['allOf'] += [Ordered]@{
            allOf = @(
            )
        }
        # re-insert 'anyOf' under new 'allOf' after tags 'allOf'
        $policyRuleHashtable['if']['allOf'] += $anyOf
        # add each tag individually to tags 'allOf'
        for ($i = 0; $i -lt $Tag.count; $i++)
        {
            # if there is atleast one tag
            if (-not [string]::IsNullOrEmpty($Tag[$i].Keys))
            {
                $policyRuleHashtable['if']['allOf'][0]['allOf'] += [Ordered]@{
                    field  = "tags.$($Tag[$i].Keys)"
                    equals = "$($Tag[$i].Values)"
                }
            }
        }
    }

    $existenceConditionList = [Ordered]@{
        allOf = [System.Collections.ArrayList]@()
    }

    $existenceConditionList['allOf'].Add([Ordered]@{
        field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus'
        equals = 'Compliant'
    })

    if ($null -ne $ParameterInfo)
    {
        $parametersExistenceCondition = Get-GuestConfigurationAssignmentParametersExistenceConditionSection -ParameterInfo $ParameterInfo
        $existenceConditionList['allOf'].Add($parametersExistenceCondition)
    }

    $policyRuleHashtable['then']['details']['existenceCondition'] = $existenceConditionList

    $auditPolicyContentHashtable['properties']['policyRule'] = $policyRuleHashtable

    $auditPolicyContent = ConvertTo-Json -InputObject $auditPolicyContentHashtable -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }
    $formattedAuditPolicyContent = Format-Json -Json $auditPolicyContent

    if (Test-Path -Path $filePath)
    {
        Write-Error -Message "A file at the policy destination path '$filePath' already exists. Please remove this file or specify a different destination path."
    }
    else
    {
        $null = New-Item -Path $filePath -ItemType 'File' -Value $formattedAuditPolicyContent
    }

    return $auditPolicyGuid
}
#EndRegion './Private/New-GuestConfigurationAuditPolicyDefinition.ps1' 636
#Region './Private/New-PesterResourceSection.ps1' 0

function New-PesterResourceSection
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $PesterFileName,

        [Parameter()]
        [String]
        $index = 1
    )

    $Version = (Get-Module -Name 'GuestConfiguration').Version.ToString()

    # this is a workaround for inserting the variable in the middle of a word inside a here-string
    $ref = '$MSFT_PesterResource'+$Index+'ref'

    # MOF should not contain the file extension since that is added by the resource
    $PesterFileName = $PesterFileName.replace('.ps1','')

    $MOFResourceSection = @"
instance of MSFT_PesterResource as $ref
{
    ModuleName = "GuestConfiguration";
    SourceInfo = "Pester scripts";
    PesterFileName = "$PesterFileName";
    ResourceID = "[PesterResource]$PesterFileName";
    ModuleVersion = "$Version";
    ConfigurationName = "$Name";
};
"@

    return $MOFResourceSection
}
#EndRegion './Private/New-PesterResourceSection.ps1' 43
#Region './Public/Copy-ChefInspecDependencies.ps1' 0
function Copy-ChefInspecDependencies
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PackagePath,

        [Parameter(Mandatory = $true)]
        [String]
        $Configuration,

        [Parameter()]
        [string]
        $ChefInspecProfilePath
    )

    # Copy Inspec install script and profiles.
    $modulePath = Join-Path $PackagePath 'Modules'
    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Configuration, 4)
    $missingDependencies = @()
    $chefInspecProfiles = @()

    $resourcesInMofDocument | ForEach-Object {
        if ($_.CimClass.CimClassName -eq 'MSFT_ChefInSpecResource')
        {
            if ([string]::IsNullOrEmpty($ChefInspecProfilePath))
            {
                throw "'$($_.CimInstanceProperties['Name'].Value)'. Please use ChefInspecProfilePath parameter to specify profile path."
            }

            $inspecProfilePath = Join-Path $ChefInspecProfilePath $_.CimInstanceProperties['Name'].Value
            if (-not (Test-Path $inspecProfilePath))
            {
                $missingDependencies += $_.CimInstanceProperties['Name'].Value
            }
            else
            {
                $chefInspecProfiles += $inspecProfilePath
            }

        }
    }

    if ($missingDependencies.Length)
    {
        throw "Failed to find Chef Inspec profile for '$($missingDependencies -join ',')'. Please make sure profile is present on $ChefInspecProfilePath path."
    }

    $chefInspecProfiles | ForEach-Object { Copy-Item $_ $modulePath -Recurse -Force -ErrorAction SilentlyContinue }

}
#EndRegion './Public/Copy-ChefInspecDependencies.ps1' 54
#Region './Public/Copy-DscResources.ps1' 0

function Copy-DscResources
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $MofDocumentPath,

        [Parameter(Mandatory = $true)]
        [String]
        $Destination,

        [Parameter()]
        [switch]
        $Force
    )

    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($MofDocumentPath, 4)

    Write-Verbose 'Copy DSC resources ...'
    $modulePath = New-Item -ItemType Directory -Force -Path (Join-Path $Destination 'Modules')
    $guestConfigModulePath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath 'GuestConfiguration')

    try
    {
        $latestModule = @()
        $latestModule += Get-Module GuestConfiguration
        $latestModule += Get-Module GuestConfiguration -ListAvailable
        $latestModule = ($latestModule | Sort-Object Version -Descending)[0]
    }
    catch
    {
        write-error 'unable to find the GuestConfiguration module either as an imported module or in $env:PSModulePath'
    }

    Copy-Item "$($latestModule.ModuleBase)/DscResources/" "$guestConfigModulePath/DscResources/" -Recurse -Force
    Copy-Item "$($latestModule.ModuleBase)/Modules/" "$guestConfigModulePath/Modules/" -Recurse -Force
    Copy-Item "$($latestModule.ModuleBase)/GuestConfiguration.psd1" "$guestConfigModulePath/GuestConfiguration.psd1" -Force
    Copy-Item "$($latestModule.ModuleBase)/GuestConfiguration.psm1" "$guestConfigModulePath/GuestConfiguration.psm1" -Force

    # Copies DSC resource modules
    $modulesToCopy = @{ }
    $IncludePesterModule = $false
    $resourcesInMofDocument.Where{
        $_.CimInstanceProperties.Name -contains 'ModuleName' -and $_.CimInstanceProperties.Name -contains 'ModuleVersion'
    }.Foreach{
        $modulesToCopy[$_.CimClass.CimClassName] = @{
            ModuleName = $_.ModuleName
            ModuleVersion = $_.ModuleVersion
        }

        if ($_.ResourceID -match 'PesterResource')
        {
            $IncludePesterModule = $true
        }
    }

    # PowerShell modules required by DSC resource module
    $powershellModulesToCopy = @{ }
    $modulesToCopy.Values.ForEach{
        if ($_.ModuleName -ne 'GuestConfiguration')
        {
            $requiredModule = Get-Module -FullyQualifiedName @{
                ModuleName = $_.ModuleName
                RequiredVersion = $_.ModuleVersion
            } -ListAvailable | Select-Object -First 1

            if (-not $requiredModule)
            {
                throw "The module '$($_.ModuleName)' with version '$($_.ModuleVersion)' could not be found."
            }

            if ($requiredModule.PSObject.Properties.Name -contains 'RequiredModules')
            {
                $requiredModule.RequiredModules | ForEach-Object {
                    if ($null -ne $_.Version)
                    {
                        $powershellModulesToCopy[$_.Name] = @{
                            ModuleName = $_.Name
                            ModuleVersion = $_.Version
                        }

                        Write-Verbose "$($_.Name) is a required PowerShell module"
                    }
                    else
                    {
                        Write-Error "Unable to add required PowerShell module $($_.Name).  No version was specified in the module manifest RequiredModules property.  Please use module specification '@{ModuleName=;ModuleVersion=}'."
                    }
                }
            }
        }
    }

    if ($true -eq $IncludePesterModule)
    {
        $latestInstalledVersionofPester = (Get-Module -Name 'Pester' -ListAvailable | Sort-Object Version -Descending)[0]
        $powershellModulesToCopy['Pester'] = @{
            ModuleName = $latestInstalledVersionofPester.Name
            ModuleVersion = $latestInstalledVersionofPester.Version
        }

        Write-Verbose "Pester is a required PowerShell module (using Pester v$($latestInstalledVersionofPester.Version))."
    }

    $modulesToCopy += $powershellModulesToCopy

    $modulesToCopy.Values | ForEach-Object {
        if (@('Pester', 'GuestConfiguration') -notcontains $_.ModuleName)
        {
            $moduleToCopy = Get-Module -FullyQualifiedName @{
                ModuleName = $_.ModuleName
                RequiredVersion = $_.ModuleVersion
            } -ListAvailable | Select-Object -First 1

            if ($null -ne $moduleToCopy)
            {
                if ($_.ModuleName -eq 'PSDesiredStateConfiguration')
                {
                    Write-Error 'The configuration includes DSC resources from the Windows PowerShell 5.1 module "PSDesiredStateConfiguration" that are not available in PowerShell Core. Switch to the "PSDSCResources" module available from the PowerShell Gallery. Note that the File and Package resources are not yet available in "PSDSCResources".'
                }

                $moduleToCopyPath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath $_.ModuleName)
                Copy-Item -Path "$($moduleToCopy.ModuleBase)/*" -Destination $moduleToCopyPath -Recurse -Force
            }
            else
            {
                Write-Error "Module $($_.ModuleName) version $($_.ModuleVersion) could not be found in `$env:PSModulePath"
            }

            $moduleToCopyPath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath $_.ModuleName)
            Copy-Item -Path "$($moduleToCopy.ModuleBase)/*" -Destination $moduleToCopyPath -Recurse -Force:$Force
        }
        elseif ($_.ModuleName -eq 'Pester')
        {
            $moduleToCopy = $latestInstalledVersionofPester
            if ($null -ne $moduleToCopy)
            {
                $moduleToCopyPath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath $_.ModuleName)
                Copy-Item -Path "$($moduleToCopy.ModuleBase)/*" -Destination $moduleToCopyPath -Recurse -Force
            }
            else
            {
                Write-Error "The configuration includes PesterResource. This resource requires Pester version 5.0.0 or later, which could not be found in `$env:PSModulePath"
            }
        }
    }

    try
    {
        # Add latest module to module path
        $latestModulePSModulePath = [IO.Path]::PathSeparator + $latestModule.ModuleBase
        $Env:PSModulePath += $latestModulePSModulePath

        # Copy binary resources.
        $nativeResourcePath = New-Item -ItemType Directory -Force -Path (Join-Path $modulePath 'DscNativeResources')
        $resources = Get-DscResource -Module @{
            ModuleName    = 'GuestConfiguration'
            ModuleVersion = $latestModule.Version.ToString()
        }

        $resources | ForEach-Object {
            if ($_.ImplementedAs -eq 'Binary')
            {
                $binaryResourcePath = Join-Path -Path (Join-Path -Path $latestModule.ModuleBase -ChildPath 'DscResources') -ChildPath $_.ResourceType
                Get-ChildItem -Path $binaryResourcePath/* -Include *.sh -Recurse | ForEach-Object { Convert-FileToUnixLineEndings -FilePath $_ }
                Copy-Item -Path $binaryResourcePath/* -Include *.sh -Destination $modulePath -Recurse -Force
                Copy-Item -Path $binaryResourcePath -Destination $nativeResourcePath -Recurse -Force
            }
        }

        # Remove DSC binaries from package (just a safeguard).
        $binaryPath = Join-Path -Path $guestConfigModulePath -ChildPath 'bin'
        $null = Remove-Item -Path $binaryPath -Force -Recurse -ErrorAction 'SilentlyContinue'
    }
    finally
    {
        # Remove addition to module path
        $Env:PSModulePath = $Env:PSModulePath.replace($latestModulePSModulePath, '')
    }
}
#EndRegion './Public/Copy-DscResources.ps1' 183
#Region './Public/New-CustomGuestConfigPolicy.ps1' 0
function New-CustomGuestConfigPolicy
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PolicyFolderPath,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $PolicyInfo
    )

    Write-Verbose -Message "Getting Policy Definitions from Current Context."

    $existingPolicies = Get-AzPolicyDefinition

    # policy.name is actually the policy id
    $existingAuditPolicy = $existingPolicies | Where-Object -FilterScript {
        ($_.name -eq $PolicyInfo.guid)
    }

    if ($null -ne $existingAuditPolicy)
    {
        Write-Verbose -Message "Policy with specified guid '$($existingAuditPolicy.Name)' already exists. Overwriting: '$($existingAuditPolicy.Properties.displayName)' ..."
    }

    New-GuestConfigurationPolicyDefinition @PSBoundParameters
}
#EndRegion './Public/New-CustomGuestConfigPolicy.ps1' 32
#Region './Public/New-GuestConfigurationDeployPolicyDefinition.ps1' 0
function New-GuestConfigurationDeployPolicyDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FileName,

        [Parameter(Mandatory = $true)]
        [String]
        $FolderPath,

        [Parameter(Mandatory = $true)]
        [String]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [String]
        $Description,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationName,

        [Parameter(Mandatory = $true)]
        [String]
        $ConfigurationVersion,

        [Parameter(Mandatory = $true)]
        [String]
        $ContentUri,

        [Parameter(Mandatory = $true)]
        [String]
        $ContentHash,

        [Parameter()]
        [AssignmentType]
        $AssignmentType,

        [Parameter(Mandatory = $true)]
        [String]
        $ReferenceId,

        [Parameter()]
        [Hashtable[]]
        $ParameterInfo,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [String]
        $Guid,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Windows', 'Linux')]
        [String]
        $Platform,

        [Parameter()]
        [bool]
        $UseCertificateValidation = $false,

        [Parameter()]
        [String]
        $Category = 'Guest Configuration',

        [Parameter()]
        [Hashtable[]]
        $Tag
    )


    $filePath = Join-Path -Path $FolderPath -ChildPath $FileName
    Write-Verbose -Message "Creating Guest Configuration Deploy Policy Definition to '$filePath'."

    $deployPolicyGuid = $Guid
    $ParameterMapping = @()
    $ParameterDefinitions = @{}
    $PolicyContentHashtable = [Ordered]@{}
    $existenceConditionList = [Ordered]@{
        allOf = [System.Collections.ArrayList]@()
    }
    $MetadataParameterMapping = @{}

    if ($null -ne $ParameterInfo)
    {
        $ParameterMapping += Get-ParameterMappingForDINE -ParameterInfo $ParameterInfo
        $ParameterDefinitions = Get-ParameterDefinition -ParameterInfo $ParameterInfo
        $MetadataParameterMapping = Get-ParameterMappingForAINE -ParameterInfo $ParameterInfo
    }

    $ParameterDefinitions['IncludeArcMachines'] += [Ordered]@{
        type          = "string"
        metadata      = [Ordered]@{
            displayName = 'Include Arc connected servers'
            description = 'By selecting this option, you agree to be charged monthly per Arc connected machine.'
        }

        allowedValues = @('True', 'False')
        defaultValue  = 'False'
    }

    $deployPolicyContentHashtable = [Ordered]@{
        properties = [Ordered]@{
            displayName = $DisplayName
            policyType  = 'Custom'
            mode        = 'Indexed'
            description = $Description
            metadata    = [Ordered]@{
                version = $ConfigurationVersion
                category          = $Category
                guestConfiguration = [Ordered]@{
                    name                   = $ConfigurationName
                    version                = $ConfigurationVersion
                    contentType            = "Custom"
                    contentUri             = $ContentUri
                    contentHash            = $ContentHash
                    configurationParameter = $MetadataParameterMapping
                }
                requiredProviders = @(
                    'Microsoft.GuestConfiguration'
                )
            }
            parameters  = $ParameterDefinitions
        }
    }

    $policyRuleHashtable = [Ordered]@{
        if   = [Ordered]@{
            anyOf = @(
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            field  = 'type'
                            equals = "Microsoft.Compute/virtualMachines"
                        }
                    )
                },
                [Ordered]@{
                    allOf = @(
                        [Ordered]@{
                            value  = "[parameters('IncludeArcMachines')]"
                            equals = "true"
                        },
                        [Ordered]@{
                            field  = "type"
                            equals = "Microsoft.HybridCompute/machines"
                        }
                    )
                }
            )
        }
        then = [Ordered]@{
            effect  = 'deployIfNotExists'
            details = [Ordered]@{
                type              = 'Microsoft.GuestConfiguration/guestConfigurationAssignments'
                name              = $ConfigurationName
                roleDefinitionIds = @('/providers/microsoft.authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c')
            }
        }
    }

    $deploymentHashtable = [Ordered]@{
        properties = [Ordered]@{
            mode       = 'incremental'
            parameters = [Ordered]@{
                vmName            = [Ordered]@{
                    value = "[field('name')]"
                }
                location          = [Ordered]@{
                    value = "[field('location')]"
                }
                type              = [Ordered]@{
                    value = "[field('type')]"
                }
                configurationName = [Ordered]@{
                    value = $ConfigurationName
                }
                contentUri        = [Ordered]@{
                    value = $ContentUri
                }
                contentHash       = [Ordered]@{
                    value = $ContentHash
                }
            }
            template   = [Ordered]@{
                '$schema'      = 'https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#'
                contentVersion = '1.0.0.0'
                parameters     = [Ordered]@{
                    vmName            = [Ordered]@{
                        type = 'string'
                    }
                    location          = [Ordered]@{
                        type = 'string'
                    }
                    type              = [Ordered]@{
                        type = 'string'
                    }
                    configurationName = [Ordered]@{
                        type = 'string'
                    }
                    contentUri        = [Ordered]@{
                        type = 'string'
                    }
                    contentHash       = [Ordered]@{
                        type = 'string'
                    }
                }
                resources      = @()
            }
        }
    }

    $guestConfigurationAssignmentHashtable = @(
        # Compute
        [Ordered]@{
            condition  = "[equals(toLower(parameters('type')), toLower('Microsoft.Compute/virtualMachines'))]"
            apiVersion = '2018-11-20'
            type       = 'Microsoft.Compute/virtualMachines/providers/guestConfigurationAssignments'
            name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/', parameters('configurationName'))]"
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                guestConfiguration = [Ordered]@{
                    name            = "[parameters('configurationName')]"
                    version         = $ConfigurationVersion
                    contentUri      = "[parameters('contentUri')]"
                    contentHash     = "[parameters('contentHash')]"
                    assignmentType  = "$AssignmentType"
                    configurationParameter = $ParameterMapping
                }
            }
        }
        # Hybrid Compute
        [Ordered]@{
            condition  = "[equals(toLower(parameters('type')), toLower('microsoft.hybridcompute/machines'))]"
            apiVersion = '2018-11-20'
            type       = 'Microsoft.HybridCompute/machines/providers/guestConfigurationAssignments'
            name       = "[concat(parameters('vmName'), '/Microsoft.GuestConfiguration/', parameters('configurationName'))]"
            location   = "[parameters('location')]"
            properties = [Ordered]@{
                guestConfiguration = [Ordered]@{
                    name        = "[parameters('configurationName')]"
                    contentUri  = "[parameters('contentUri')]"
                    contentHash = "[parameters('contentHash')]"
                    assignmentType  = "$AssignmentType"
                    version     = $ConfigurationVersion
                    configurationParameter = $ParameterMapping
                }
            }
        }
    )

    if ($Platform -ieq 'Windows')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = "Microsoft.Compute/imagePublisher"
                        in    = @(
                            'esri',
                            'incredibuild',
                            'MicrosoftDynamicsAX',
                            'MicrosoftSharepoint',
                            'MicrosoftVisualStudio',
                            'MicrosoftWindowsDesktop',
                            'MicrosoftWindowsServerHPCPack'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'MicrosoftWindowsServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'MicrosoftSQLServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageOffer'
                                notLike = 'SQL2008*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'dsvm-windows'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'standard-data-science-vm',
                                    'windows-data-science-vm'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'batch'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'rendering-windows2016'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'cis-windows-server-201*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'pivotal'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'bosh-windows-server*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloud-infrastructure-services'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'ad*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                anyOf = @(
                                    [Ordered]@{
                                        field  = 'Microsoft.Compute/virtualMachines/osProfile.windowsConfiguration'
                                        exists = 'true'
                                    },
                                    [Ordered]@{
                                        field = 'Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType'
                                        like  = 'Windows*'
                                    }
                                )
                            },
                            [Ordered]@{
                                anyOf = @(
                                    [Ordered]@{
                                        field  = 'Microsoft.Compute/imageSKU'
                                        exists = 'false'
                                    },
                                    [Ordered]@{
                                        allOf = @(
                                            [Ordered]@{
                                                field   = 'Microsoft.Compute/imageSKU'
                                                notLike = '2008*'
                                            },
                                            [Ordered]@{
                                                field   = 'Microsoft.Compute/imageOffer'
                                                notLike = 'SQL2008*'
                                            }
                                        )
                                    }
                                )
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'windows*'
            }
        )
    }
    elseif ($Platform -ieq 'Linux')
    {
        $policyRuleHashtable['if']['anyOf'][0]['allOf'] += @(
            [Ordered]@{
                anyOf = @(
                    [Ordered]@{
                        field = 'Microsoft.Compute/imagePublisher'
                        in    = @(
                            'microsoft-aks',
                            'qubole-inc',
                            'datastax',
                            'couchbase',
                            'scalegrid',
                            'checkpoint',
                            'paloaltonetworks'
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'OpenLogic'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'CentOS*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Oracle'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Oracle-Linux'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'RHEL',
                                    'RHEL-HA'
                                    'RHEL-SAP',
                                    'RHEL-SAP-APPS',
                                    'RHEL-SAP-HA',
                                    'RHEL-SAP-HANA'
                                )
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'RedHat'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'osa',
                                    'rhel-byos'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'center-for-internet-security-inc'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'cis-centos-7-l1',
                                    'cis-centos-7-v2-1-1-l1'
                                    'cis-centos-8-l1',
                                    'cis-debian-linux-8-l1',
                                    'cis-debian-linux-9-l1',
                                    'cis-nginx-centos-7-v1-1-0-l1',
                                    'cis-oracle-linux-7-v2-0-0-l1',
                                    'cis-oracle-linux-8-l1',
                                    'cis-postgresql-11-centos-linux-7-level-1',
                                    'cis-rhel-7-l2',
                                    'cis-rhel-7-v2-2-0-l1',
                                    'cis-rhel-8-l1',
                                    'cis-suse-linux-12-v2-0-0-l1',
                                    'cis-ubuntu-linux-1604-v1-0-0-l1',
                                    'cis-ubuntu-linux-1804-l1'

                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'credativ'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'Debian'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '7*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Suse'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'SLES*'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '11*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'Canonical'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'UbuntuServer'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '12*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-dsvm'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                in    = @(
                                    'linux-data-science-vm-ubuntu',
                                    'azureml'
                                )
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-centos-os'
                            },
                            [Ordered]@{
                                field   = 'Microsoft.Compute/imageSKU'
                                notLike = '6*'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'cloudera'
                            },
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imageOffer'
                                equals = 'cloudera-altus-centos-os'
                            }
                        )
                    },
                    [Ordered]@{
                        allOf = @(
                            [Ordered]@{
                                field  = 'Microsoft.Compute/imagePublisher'
                                equals = 'microsoft-ads'
                            },
                            [Ordered]@{
                                field = 'Microsoft.Compute/imageOffer'
                                like  = 'linux*'
                            }
                        )
                    }
                )
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = "Microsoft.HybridCompute/imageOffer"
                like  = "linux*"
            }
        )

        $policyRuleHashtable['if']['anyOf'][1]['allOf'] += @(
            [Ordered]@{
                field = 'Microsoft.HybridCompute/imageOffer'
                like  = 'linux*'
            }
        )

    }
    else
    {
        throw "The specified platform '$Platform' is not currently supported by this script."
    }

    # If there is at least one tag
    if ($PSBoundParameters.ContainsKey('Tag') -AND $null -ne $Tag)
    {
        # Capture existing 'anyOf' section
        $anyOf = $policyRuleHashtable['if']
        # Replace with new 'allOf' at top order
        $policyRuleHashtable['if'] = [Ordered]@{
            allOf = @(
            )
        }

        # Add tags section under new 'allOf'
        $policyRuleHashtable['if']['allOf'] += [Ordered]@{
            allOf = @(
            )
        }

        # Re-insert 'anyOf' under new 'allOf' after tags 'allOf'
        $policyRuleHashtable['if']['allOf'] += $anyOf
        # Add each tag individually to tags 'allOf'
        for ($i = 0; $i -lt $Tag.count; $i++)
        {
            # If there is at least one tag
            if (-not [string]::IsNullOrEmpty($Tag[$i].Keys))
            {
                $policyRuleHashtable['if']['allOf'][0]['allOf'] += [Ordered]@{
                    field  = "tags.$($Tag[$i].Keys)"
                    equals = "$($Tag[$i].Values)"
                }
            }
        }
    }

    # Handle adding parameters if needed
    if ($null -ne $ParameterInfo -and $ParameterInfo.Count -gt 0)
    {
        $parameterValueConceatenatedStringList = @()

        if (-not $deployPolicyContentHashtable['properties'].Contains('parameters'))
        {
            $deployPolicyContentHashtable['properties']['parameters'] = [Ordered]@{ }
        }

        foreach ($guestConfigurationAssignment in $guestConfigurationAssignmentHashtable)
        {
            if (-not $guestConfigurationAssignment['properties']['guestConfiguration'].Contains('configurationParameter'))
            {
                $guestConfigurationAssignment['properties']['guestConfiguration']['configurationParameter'] = @()
            }
        }

        # Parameter Hash Section
        $parameterValueConceatenatedStringList = @()
        foreach ($parameterPair in $ParameterMapping) {
            $name = $parameterPair.name
            $value = $parameterPair.value -replace "[][]",""

            $currentParameterValueConcatenatedString = "'$name', '=', $value"
            $parameterValueConceatenatedStringList += $currentParameterValueConcatenatedString
        }

        $allParameterValueConcantenatedString = $parameterValueConceatenatedStringList -join ", ',', "
        $parameterExistenceConditionEqualsValue = "[base64(concat($allParameterValueConcantenatedString))]"
        $existenceConditionList['allOf'].Add([Ordered]@{
            field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/parameterHash'
            equals = $parameterExistenceConditionEqualsValue
        })

        # Adding parameters into the deploymentHashTable
        foreach ($currentParameterInfo in $parameterInfo)
        {
            # Add values in Deployment > Properties > Parameter section
            if ($currentParameterInfo.ContainsKey('DeploymentValue'))
            {
                $deploymentHashtable['properties']['parameters'] += [Ordered]@{
                    $currentParameterInfo.ReferenceName = [Ordered]@{
                        value = $currentParameterInfo.DeploymentValue
                    }
                }
            }
            else
            {
                $deploymentHashtable['properties']['parameters'] += [Ordered]@{
                    $currentParameterInfo.ReferenceName = [Ordered]@{
                        value = "[parameters('$($currentParameterInfo.ReferenceName)')]"
                    }
                }
            }

            # Add Type to Deployment > Properties > Template > Parameters section
            $deploymentHashtable['properties']['template']['parameters'] += [Ordered]@{
                $currentParameterInfo.ReferenceName = [Ordered]@{
                    type = $currentParameterInfo.Type
                }
            }
        }
    }

    # Existence Condition section
    $existenceConditionList['allOf'].Add([Ordered]@{
        field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/contentHash'
        equals = "$ContentHash"
    })
    $existenceConditionList['allOf'].Add([Ordered]@{
        field  = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/complianceStatus'
        equals = 'Compliant'
    })

    $policyRuleHashtable['then']['details']['existenceCondition'] = $existenceConditionList

    # Deployment Section
    $policyRuleHashtable['then']['details']['deployment'] = $deploymentHashtable
    $policyRuleHashtable['then']['details']['deployment']['properties']['template']['resources'] += $guestConfigurationAssignmentHashtable
    $deployPolicyContentHashtable['properties']['policyRule'] = $policyRuleHashtable

    $deployPolicyContentHashtable += [Ordered]@{
        id   = "/providers/Microsoft.Authorization/policyDefinitions/$deployPolicyGuid"
        type = "Microsoft.Authorization/policyDefinitions"
        name = $deployPolicyGuid
    }

    $deployPolicyContent = ConvertTo-Json -InputObject $deployPolicyContentHashtable -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }
    $formattedDeployPolicyContent = Format-Json -Json $deployPolicyContent

    if (Test-Path -Path $filePath)
    {
        Write-Error -Message "A file at the policy destination path '$filePath' already exists. Please remove this file or specify a different destination path."
    }
    else
    {
        $null = New-Item -Path $filePath -ItemType 'File' -Value $formattedDeployPolicyContent
    }

    return $deployPolicyGuid
}
#EndRegion './Public/New-GuestConfigurationDeployPolicyDefinition.ps1' 795
#Region './Public/New-GuestConfigurationPolicyDefinition.ps1' 0

<#
    .SYNOPSIS
        Creates a new policy for guest configuration.

    .PARAMETER PolicyFolderPath
        Folder where policy exists.

    .PARAMETER PolicyInfo
        Policy information.

    .EXAMPLE
        $PolicyInfo = @{
            FileName                 = $FileName
            DisplayName              = $DisplayName
            Description              = $Description
            Platform                 = $Platform
            ConfigurationName        = $policyName
            ConfigurationVersion     = $Version
            ContentUri               = $ContentUri
            ContentHash              = $contentHash
            AssignmentType           = $Mode
            ReferenceId              = "Deploy_$policyName"
            ParameterInfo            = $ParameterInfo
            UseCertificateValidation = $packageIsSigned
            Category                 = $Category
            Tag                      = $Tag
        }
        New-GuestConfigurationPolicyDefinition -PolicyFolderPath $policyDefinitionsPath -PolicyInfo $PolicyInfo

#>
function New-GuestConfigurationPolicyDefinition
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $PolicyFolderPath,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $PolicyInfo
    )

    Write-Verbose -Message "Creating new Guest Configuration Policy to '$PolicyFolderPath'."

    if (Test-Path -Path $PolicyFolderPath)
    {
        $null = Remove-Item -Path $PolicyFolderPath -Force -Recurse -ErrorAction 'SilentlyContinue'
    }

    $null = New-Item -Path $PolicyFolderPath -ItemType 'Directory'

    if ($PolicyInfo.FileName -eq 'DeployIfNotExists.json')
    {
        foreach ($currentDeployPolicyInfo in $PolicyInfo)
        {
            $currentDeployPolicyInfo['FolderPath'] = $PolicyFolderPath
            New-GuestConfigurationDeployPolicyDefinition @currentDeployPolicyInfo
        }
    }
    else
    {
        foreach ($currentAuditPolicyInfo in $PolicyInfo)
        {
            $currentAuditPolicyInfo['FolderPath'] = $PolicyFolderPath
            New-GuestConfigurationAuditPolicyDefinition @currentAuditPolicyInfo
        }
    }
}
#EndRegion './Public/New-GuestConfigurationPolicyDefinition.ps1' 72
#Region './Public/New-MofFileforPester.ps1' 0

function New-MofFileforPester
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Name,

        [Parameter(Mandatory = $true)]
        [System.String]
        $PesterScriptsPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    Write-Verbose "Getting Pester script files from '$PesterScriptsPath'"
    $Scripts = Get-ChildItem $PesterScriptsPath -Filter "*.ps1"

    $MOFContent = ''

    # Create resource section of MOF for each script
    $index = 1
    foreach ($script in $Scripts)
    {
        $ResourceSection = $null
        $ResourceSection = New-PesterResourceSection -Name $Name -PesterFileName $script.Name -Index $index
        $index++
        $MOFContent += $ResourceSection
        $MOFContent += "`n"
    }

    # Append configuration info
    $MOFContent += @"
instance of OMI_ConfigurationDocument
{
    Version="2.0.0";
    MinimumCompatibleVersion = "1.0.0";
    CompatibleVersionAdditionalProperties= {"Omi_BaseResource:ConfigurationName"};
    Name="$Name";
};
"@

    # Write file
    Set-Content -Value $MOFContent -Path $Path -Force:$Force

    # Output the path to the new file
    [PSCustomObject]@{
        Path = $Path
    }
}
#EndRegion './Public/New-MofFileforPester.ps1' 59
#Region './Public/Save-GuestConfigurationMofDocument.ps1' 0
function Save-GuestConfigurationMofDocument
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,

        [Parameter(Mandatory = $true)]
        [String]
        $SourcePath,

        [Parameter(Mandatory = $true)]
        [String]
        $DestinationPath
    )

    $resourcesInMofDocument = Get-GuestConfigurationMofContent -Name $Name -Path $SourcePath

    # if mof contains Chef resource
    if ($resourcesInMofDocument.CimSystemProperties.ClassName -contains 'MSFT_ChefInSpecResource')
    {
        Write-Verbose -Message "Serialize DSC document to $DestinationPath path ..."
        $content = ''
        for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++)
        {
            $resourceClassName = $resourcesInMofDocument[$i].CimSystemProperties.ClassName
            $content += "instance of $resourceClassName"

            if ($resourceClassName -ne 'OMI_ConfigurationDocument')
            {
                $content += ' as $' + "$resourceClassName$i"
            }

            $content += "`n{`n"
            $resourcesInMofDocument[$i].CimInstanceProperties | ForEach-Object {
                $content += " $($_.Name)"
                if ($_.CimType -eq 'StringArray')
                {
                    $content += " = {""$($_.Value -replace '[""\\]','\$&')""}; `n"
                }
                else
                {
                    $content += " = ""$($_.Value -replace '[""\\]','\$&')""; `n"
                }
            }

            $content += "};`n" ;
        }

        $content | Out-File $DestinationPath
    }
    else
    {
        Write-Verbose "Copy DSC document to $DestinationPath path ..."
        Copy-Item $SourcePath $DestinationPath
    }
}
#EndRegion './Public/Save-GuestConfigurationMofDocument.ps1' 60
#Region './Public/Test-GuestConfigurationMofResourceDependencies.ps1' 0
function Test-GuestConfigurationMofResourceDependencies
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )

    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++)
    {
        if ($resourcesInMofDocument[$i].CimInstanceProperties.Name -contains 'ModuleName' -and $resourcesInMofDocument[$i].ModuleName -ne 'GuestConfiguration')
        {
            if ($resourcesInMofDocument[$i].ModuleName -ieq 'PsDesiredStateConfiguration')
            {
                throw "'PsDesiredStateConfiguration' module is not supported by GuestConfiguration. Please use 'PSDSCResources' module instead of 'PsDesiredStateConfiguration' module in DSC configuration."
            }

            $configurationName = $resourcesInMofDocument[$i].ConfigurationName
            Write-Warning -Message "The configuration '$configurationName' is using one or more resources outside of the GuestConfiguration module. Please make sure these resources work with PowerShell Core"
            break
        }
    }
}
#EndRegion './Public/Test-GuestConfigurationMofResourceDependencies.ps1' 28
#Region './Public/Update-MofDocumentParameters.ps1' 0
function Update-MofDocumentParameters
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter()]
        [Hashtable[]]
        $Parameter
    )

    if ($Parameter.Count -eq 0)
    {
        return
    }

    $resourcesInMofDocument = [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($Path, 4)

    foreach ($parmInfo in $Parameter)
    {
        if (-not $parmInfo.Contains('ResourceType'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourceType'. Please make sure that configuration resource type is specified in configuration parameter."
        }

        if (-not $parmInfo.Contains('ResourceId'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourceId'. Please make sure that configuration resource Id is specified in configuration parameter."
        }

        if (-not $parmInfo.Contains('ResourcePropertyName'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourcePropertyName'. Please make sure that configuration resource property name is specified in configuration parameter."
        }

        if (-not $parmInfo.Contains('ResourcePropertyValue'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourcePropertyValue'. Please make sure that configuration resource property value is specified in configuration parameter."
        }

        $resourceId = "[$($parmInfo.ResourceType)]$($parmInfo.ResourceId)"
        if ($null -eq (
                $resourcesInMofDocument | Where-Object {
                        ($_.CimInstanceProperties.Name -contains 'ResourceID') -and
                        ($_.CimInstanceProperties['ResourceID'].Value -eq $resourceId) -and
                        ($_.CimInstanceProperties.Name -contains $parmInfo.ResourcePropertyName)
                })
            )
        {
            throw "Failed to find parameter reference in the configuration '$Path'. Please make sure parameter with ResourceType:'$($parmInfo.ResourceType)', ResourceId:'$($parmInfo.ResourceId)' and ResourcePropertyName:'$($parmInfo.ResourcePropertyName)' exist in the configuration."
        }

        Write-Verbose "Updating configuration parameter for $resourceId ..."
        $resourcesInMofDocument | ForEach-Object {
            if (($_.CimInstanceProperties.Name -contains 'ResourceID') -and ($_.CimInstanceProperties['ResourceID'].Value -eq $resourceId))
            {
                $item = $_.CimInstanceProperties.Item($parmInfo.ResourcePropertyName)
                $item.Value = $parmInfo.ResourcePropertyValue
            }
        }
    }

    Write-Verbose "Saving configuration file '$Path' with updated parameters ..."
    $content = ""
    for ($i = 0; $i -lt $resourcesInMofDocument.Count; $i++)
    {
        $resourceClassName = $resourcesInMofDocument[$i].CimSystemProperties.ClassName
        $content += "instance of $resourceClassName"

        if ($resourceClassName -ne 'OMI_ConfigurationDocument')
        {
            $content += ' as $' + "$resourceClassName$i"
        }

        $content += "`n{`n"
        $resourcesInMofDocument[$i].CimInstanceProperties | ForEach-Object {
            $content += " $($_.Name)"
            if ($_.CimType -eq 'StringArray')
            {
                $content += " = {""$($_.Value -replace '[""\\]','\$&')""}; `n"
            }
            else
            {
                $content += " = ""$($_.Value -replace '[""\\]','\$&')""; `n"
            }
        }

        $content += "};`n" ;
    }

    $content | Out-File $Path
}
#EndRegion './Public/Update-MofDocumentParameters.ps1' 96
#Region './Public/Update-PolicyParameter.ps1' 0
function Update-PolicyParameter
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Hashtable[]]
        $parameter
    )

    $updatedParameterInfo = @()

    foreach ($parmInfo in $Parameter)
    {
        $param = @{ }
        $param['Type'] = 'string'

        if ($parmInfo.Contains('Name'))
        {
            $param['ReferenceName'] = $parmInfo.Name
        }
        else
        {
            throw "Policy parameter is missing a mandatory property 'Name'. Please make sure that parameter name is specified in Policy parameter."
        }

        if ($parmInfo.Contains('DisplayName'))
        {
            $param['DisplayName'] = $parmInfo.DisplayName
        }
        else
        {
            throw "Policy parameter is missing a mandatory property 'DisplayName'. Please make sure that parameter display name is specified in Policy parameter."
        }

        if ($parmInfo.Contains('Description'))
        {
            $param['Description'] = $parmInfo.Description
        }

        if (-not $parmInfo.Contains('ResourceType'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourceType'. Please make sure that configuration resource type is specified in Policy parameter."
        }
        elseif (-not $parmInfo.Contains('ResourceId'))
        {
            throw "Policy parameter is missing a mandatory property 'ResourceId'. Please make sure that configuration resource Id is specified in Policy parameter."
        }
        else
        {
            $param['MofResourceReference'] = "[$($parmInfo.ResourceType)]$($parmInfo.ResourceId)"
        }

        if ($parmInfo.Contains('ResourcePropertyName'))
        {
            $param['MofParameterName'] = $parmInfo.ResourcePropertyName
        }
        else
        {
            throw "Policy parameter is missing a mandatory property 'ResourcePropertyName'. Please make sure that configuration resource property name is specified in Policy parameter."
        }

        if ($parmInfo.Contains('DefaultValue'))
        {
            $param['DefaultValue'] = $parmInfo.DefaultValue
        }

        if ($parmInfo.Contains('AllowedValues'))
        {
            $param['AllowedValues'] = $parmInfo.AllowedValues
        }

        $updatedParameterInfo += $param;
    }

    return $updatedParameterInfo
}
#EndRegion './Public/Update-PolicyParameter.ps1' 78

# SIG # Begin signature block
# MIIjkQYJKoZIhvcNAQcCoIIjgjCCI34CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKWja5Do6dNYUC
# AZRNyBUoTWUB34RfxRh/fuhBcaKWLqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVZjCCFWICAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgabiGdjGj
# Cn8dgLULqaGYovAwPd4ckfFwtRy4C3uBvAkwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQAX8JPMdX5TDMAtkzpR6uoHHA7NiBT74nVVO3IO7fmt
# nff4qKX8RklGlyHRqjQHKY8SgVZ/Csh/bWld375qDY1FgpyHtVvwSdHq/3Yc8mk8
# Tz1PLGMjVTSbJmV90N1Ql2eef89MQsa5/uKab9kWXe9+krF+iyeaqSHFy4fe4dY4
# OXHekvCtAsd3pLt6/gKso6jsMqzHiLzBcqhwdhF/zBE+ZQeFfhzHnOL5lJMkDcPr
# METEoUFCUDc+4U5iNCq0ih/lCIKodGn/15jE4InSb1WBR68T0vX1xCNo5SfRv2rG
# pyibptOryo7BZRJ9nw70nMlt6m9pDAEBHEcduKpFfhAMoYIS8DCCEuwGCisGAQQB
# gjcDAwExghLcMIIS2AYJKoZIhvcNAQcCoIISyTCCEsUCAQMxDzANBglghkgBZQME
# AgEFADCCAVQGCyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIFYTtjxYsRJSySxaOWxuv+u8nNMulh7uorw/1/RD
# FNWuAgZhggVAXQ8YEjIwMjExMTA4MTgyNjM5LjE5WjAEgAIB9KCB1KSB0TCBzjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWlj
# cm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBU
# U1MgRVNOOjMyQkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1T
# dGFtcCBTZXJ2aWNloIIORDCCBPUwggPdoAMCAQICEzMAAAFi0P4C8wHlzUkAAAAA
# AWIwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# HhcNMjEwMTE0MTkwMjIyWhcNMjIwNDExMTkwMjIyWjCBzjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJh
# dGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMyQkQt
# RTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA74ah1Pa5wvcyvYNCy/YQ
# s1tK8rIGlh1Qq1QFaJmYVXLXykb+m5yCStzmL227wJjsalZX8JA2YcbaZV5Icwm9
# vAJz8AC/sk/dsUK3pmDvkhtVI04YDV6otuZCILpQB9Ipcs3d0e1Dl2KKFvdibOk0
# /0rRxU9l+/Yxeb5lVTRERLxzI+Rd6Xv5QQYT6Sp2IE0N1vzIFd3yyO773T5XifNg
# L5lZbtIUnYUVmUBKlVoemO/54aiFeVBpIG+YzhDTF7cuHNAzxWIbP1wt4VIqAV9J
# juqLMvvBSD56pi8NTKM9fxrERAeaTS2HbfBYfmnRZ27Czjeo0ijQ5DSZGi0ErvWf
# KQIDAQABo4IBGzCCARcwHQYDVR0OBBYEFMvEShFgSkO3OnzgHlaVk3aQ/iprMB8G
# A1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Rp
# bVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3Rh
# UENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwDQYJKoZIhvcNAQELBQADggEBAC1BrcOhdhtb9xcAJtxVIUZ7iALwZewX
# FIdPcmDAVT810k5xuRwVNW9Onq+WZO8ebqwiOSdEEHReLU0FOo/DbS7q79PsKdz/
# PSBPqZ/1ysjRVH0L5HUK2N7NgpkR1lnt+41BaOzJ+00OFDL5GqeqvK3RWh7MtqWF
# 6KKcfNkP/hjiFlg9/S7xNK/Vl8q10HB5YbdBTQun8j1Jsih6YMb3tFQsxw++ra5+
# FSnc4yJhAYvVaqTKRKepEmwzYhwDiXh2ag80/p0uDkOvs1WhgogwidpBVmNLAMxm
# FavK9+LNfRKvPIuCQw+EsxWR8vFBBJDfs14WTsXVF94CQ1YCHqYI5EEwggZxMIIE
# WaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0y
# NTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RU
# ENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBE
# D/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50
# YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd
# /XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaR
# togINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQAB
# o4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8
# RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIB
# hjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fO
# mhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9w
# a2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggr
# BgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSAB
# Af8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEF
# BQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBt
# AGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Eh
# b7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7
# uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqR
# UgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9
# Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8
# +n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+
# Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh
# 2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRy
# zR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoo
# uLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx
# 16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341
# Hgi62jbb01+P3nSISRKhggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9w
# ZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjMy
# QkQtRTNENS0zQjFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2
# aWNloiMKAQEwBwYFKw4DAhoDFQCas/oKGtvPRrHuznufk+indULyDKCBgzCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA
# 5TPDyjAiGA8yMDIxMTEwODE5NDIwMloYDzIwMjExMTA5MTk0MjAyWjB3MD0GCisG
# AQQBhFkKBAExLzAtMAoCBQDlM8PKAgEAMAoCAQACAiF6AgH/MAcCAQACAhShMAoC
# BQDlNRVKAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAFU2JYQKPJe7Nk0yd
# SjPnkSlZOMrZGcCTDtqbQ0F+DNCrR7VnoDQzO9RUBAQZ8DGesSFQAH5DWtrJDWcC
# p7lu2GJl0Dew1ahWYk30vX2HD4p2vrOaxpgKpqTI82VIP/IDBIwwdROH6I74fGfG
# 1bU2a1zICU5ZZfKb248qRaDVB7UxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAWLQ/gLzAeXNSQAAAAABYjANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCBTxlxFcdjaDBROEmaj1h2QaZxHJw6KS6Ki+0ynFUliXDCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIIqqGJX7PA0OulTsNEHsyLnvGLoYE1iwaOBmqrap
# UwoyMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFi
# 0P4C8wHlzUkAAAAAAWIwIgQgOfxnVfvB+3QeY+pnxfaH+F6BrStdH2cz4qhIB263
# VlswDQYJKoZIhvcNAQELBQAEggEAfYZno3JqGkSdzV9AuyKDhiTlwDJgbSXnYqCV
# WiqvRj6Z/V4JBRvWnEKklPeQ7fTS9ofF0mRf0MRbwAbghZxBj2NgHLVLzVfH8jhu
# F4uOguqE7Ph/G4UGIqleXLiN0nm4uPhJftf7fgjt6HmbuLbRzG8IKLGcXkXSa15C
# uqzASqsd6v3+lDATTsG0R8wEUgrqR3WhJxU3KTwtLqfVUuGO4h0ejGtNrDUU26ZR
# xh8nbRLDNfUJ6tvFAi7e9VPJP9VuyL7HVatxyEyFDDF40xoZL2O6U1WI9UFP3Han
# ZUM8wGPTieDSOMXQs9Hhz1ln5EXiBtVrtHHuWS50ADnrJgb4KQ==
# SIG # End signature block
