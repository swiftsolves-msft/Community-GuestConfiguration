#Region './prefix.ps1' 0
Set-StrictMode -Version latest
$ErrorActionPreference = 'Stop'
$ReleaseVersion = '0.0.0'
#EndRegion './prefix.ps1' 4
#Region './Private/Get-GuestConfigPath.ps1' 0
function Get-GuestConfigPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    $platform = Get-OSPlatform

    if ($platform -eq 'Windows')
    {
        Join-path -Path $env:ProgramData -ChildPath 'GuestConfig'
    }
    else
    {
        '/var/lib/GuestConfig'
    }
}
#EndRegion './Private/Get-GuestConfigPath.ps1' 18
#Region './Public/Get-GuestConfigAssignmentReportFilePath.ps1' 0
function Get-GuestConfigAssignmentReportFilePath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ConfigurationName
    )

    $guestConfigReportFolderPath = Get-GuestConfigAssignmentReportFolderPath -ConfigurationName $ConfigurationName

    $reportFilePath = Join-Path $guestConfigReportFolderPath "$($ConfigurationName)_Compliant.json"
    if(Test-Path $reportFilePath) {
        return $reportFilePath
    }

    $reportFilePath = Join-Path $guestConfigReportFolderPath "$($ConfigurationName)_NonCompliant.json"
    if(Test-Path $reportFilePath) {
        return $reportFilePath
    }

    throw "Failed to find assignment report at '$($guestConfigReportFolderPath)' location"
}
#EndRegion './Public/Get-GuestConfigAssignmentReportFilePath.ps1' 27
#Region './Public/Get-GuestConfigAssignmentReportFolderPath.ps1' 0
function Get-GuestConfigAssignmentReportFolderPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ConfigurationName
    )

    $binRootFolder = Get-GuestConfigBinaryRootPath
    $releaseVersionfolder = Join-Path -Path $binRootFolder -ChildPath $global:ReleaseVersion
    $guestConfigReportFolderPath = Join-Path -Path $releaseVersionfolder -ChildPath 'reports'
    return $guestConfigReportFolderPath
}
#EndRegion './Public/Get-GuestConfigAssignmentReportFolderPath.ps1' 18
#Region './Public/Get-GuestConfigBinaryPath.ps1' 0
function Get-GuestConfigBinaryPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param ()

    $binRootFolder = Get-GuestConfigBinaryRootPath
    $releaseVersionfolder = Join-Path -Path $binRootFolder -ChildPath $global:ReleaseVersion
    $guestConfigBinaryPath = Join-Path -Path $releaseVersionfolder -ChildPath 'GC'
    Write-Debug -Message "Guest Config Binary Path is: '$guestConfigBinaryPath'."

    $guestConfigBinaryPath
}
#EndRegion './Public/Get-GuestConfigBinaryPath.ps1' 15
#Region './Public/Get-GuestConfigBinaryRootPath.ps1' 0

function Get-GuestConfigBinaryRootPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    Join-Path -Path (Get-GuestConfigPath) -ChildPath 'bin'
}
#EndRegion './Public/Get-GuestConfigBinaryRootPath.ps1' 10
#Region './Public/Get-GuestConfigLogPath.ps1' 0
function Get-GuestConfigLogPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param ()

    $logFolder = Join-Path -Path (Get-GuestConfigPath) -ChildPath 'gc_agent_logs'
    $logPath = Join-Path -Path $logFolder -ChildPath 'gc_agent.json'

    return $logPath
}
#EndRegion './Public/Get-GuestConfigLogPath.ps1' 13
#Region './Public/Get-GuestConfigPolicyPath.ps1' 0
function Get-GuestConfigPolicyPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    Join-path -Path $(Get-GuestConfigPath) -ChildPath 'policy'
}
#EndRegion './Public/Get-GuestConfigPolicyPath.ps1' 9
#Region './Public/Get-GuestConfigurationModulePath.ps1' 0
function Get-GuestConfigurationModulePath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    (Get-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath '..')).Parent.FullName
}
#EndRegion './Public/Get-GuestConfigurationModulePath.ps1' 9
#Region './Public/Get-GuestConfigWorkerBinaryPath.ps1' 0
function Get-GuestConfigWorkerBinaryPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param ()

    $gcBinPath = Get-GuestConfigBinaryPath
    $gcWorkerPath = Join-Path $gcBinPath 'gc_worker.exe'

    if (-not $IsWindows)
    {
        $gcWorkerPath = Join-Path $gcBinPath 'gc_worker'
    }

    return $gcWorkerPath
}
#EndRegion './Public/Get-GuestConfigWorkerBinaryPath.ps1' 18
#Region './Public/Get-InspecProfilePath.ps1' 0
function Get-InspecProfilePath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    Join-Path -Path $(Get-GuestConfigBinaryPath) -ChildPath 'inspec'
}
#EndRegion './Public/Get-InspecProfilePath.ps1' 9
#Region './Public/Get-OSPlatform.ps1' 0
function Get-OSPlatform
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param ()

    $platform = 'Windows'

    if ($PSVersionTable.PSEdition -eq 'Desktop')
    {
        $platform = 'Windows'
    }
    elseif ($PSVersionTable.PSEdition -eq 'Core')
    {
        if ($IsWindows)
        {
            $platform = 'Windows'
        }
        elseif ($IsLinux)
        {
            $platform = 'Linux'
        }
        elseif ($IsMacOS)
        {
            $platform = 'MacOS'
        }
    }

    $platform
}
#EndRegion './Public/Get-OSPlatform.ps1' 31
#Region './Public/InitReleaseVersionInfo.ps1' 0

function InitReleaseVersionInfo
{
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Version
    )

    $global:ReleaseVersion = $Version
}
#EndRegion './Public/InitReleaseVersionInfo.ps1' 14
#Region './Public/Write-GCOperationConsoleMessages.ps1' 0
function Write-GCOperationConsoleMessages
{
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    param ()

    $logPath = Get-GuestConfigLogPath
    $logs = ConvertFrom-Json (Get-Content $logPath -Raw)
    $logs | % {
        if($_.type -eq 'warning')
        {
            Write-Warning $_.message
        }
        elseif($_.type -eq 'error')
        {
            Write-Error $_.message
        }
        else
        {
            Write-Verbose $_.message
        }
    }
}
#EndRegion './Public/Write-GCOperationConsoleMessages.ps1' 24

# SIG # Begin signature block
# MIIjlgYJKoZIhvcNAQcCoIIjhzCCI4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDqmIzSayuEgQn/
# TITRvkxAy6LbrI4m9S3NOBUdW3acwqCCDYUwggYDMIID66ADAgECAhMzAAAB4HFz
# JMpcmPgZAAAAAAHgMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ2WhcNMjExMjAyMjEzMTQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDRXpc9eiGRI/2BlmU7OMiQPTKpNlluodjT2rltPO/Gk47bH4gBShPMD4BX/4sg
# NvvBun6ZOG2dxUW30myWoUJJ0iRbTAv2JFzjSpVQvPE+D5vtmdu6WlOR2ahF4leF
# 5Vvk4lPg2ZFrqg5LNwT9gjwuYgmih+G2KwT8NMWusBhO649F4Ku6B6QgA+vZld5S
# G2XWIdvS0pmpmn/HFrV4eYTsl9HYgjn/bPsAlfWolLlEXYTaCljK7q7bQHDBrzlR
# ukyyryFpPOR9Wx1cxFJ6KBqg2jlJpzxjN3udNJPOqarnQIVgB8DUm3I5g2v5xTHK
# Ovz9ucN21467cYcIxjPC4UkDAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUVBWIZHrG4UIX3uX4142l+8GsPXAw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2MzAxMDAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AE5msNzmYzYbNgpnhya6YsrM+CIC8CXDu10nwzZtkgQciPOOqAYmFcWJCwD5VZzs
# qFwad8XIOrfCylWf4hzn09mD87yuazpuCstLSqfDLNd3740+254vEZqdGxOglAGU
# ih2IiF8S0GDwucpLGzt/OLXPFr/d4MWxPuX0L+HB5lA3Y/CJE673dHGQW2DELdqt
# ohtkhp+oWFn1hNDDZ3LP++HEZvA7sI/o/981Sh4kaGayOp6oEiQuGeCXyfrIC9KX
# eew0UlYX/NHVDqr4ykKkqpHtzbUbuo7qovUHPbYKcRGWrrEtBS5SPLFPumqsRtzb
# LgU9HqfRAN36bMsd2qynGyWBVFOM7NMs2lTCGM85Z/Fdzv/8tnYT36Cmbue+IM+6
# kS86j6Ztmx0VIFWbOvNsASPT6yrmYiecJiP6H0TrYXQK5B3jE8s53l+t61ab0Eul
# 7DAxNWX3lAiUlzKs3qZYQEK1LFvgbdTXtBRnHgBdABALK3RPrieIYqPln9sAmg3/
# zJZi4C/c2cWGF6WwK/w1Nzw08pj7jaaZZVBpCeDe+y7oM26QIXxracot7zJ21/TL
# 70biK36YybSUDkjhQPP/uxT0yebLNBKk7g8V98Wna2MsHWwk0sgqpkjIp02TrkVz
# 26tcF2rml2THRSDrwpBa4x9c8rM8Qomiyeh2tEJnsx2LMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCFWcwghVjAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAHgcXMkylyY+BkAAAAA
# AeAwDQYJYIZIAWUDBAIBBQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKaw
# vQhlHYOWMCxkGih+8mpI7wUSF8WraMpRGpfHi17nMEIGCisGAQQBgjcCAQwxNDAy
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20wDQYJKoZIhvcNAQEBBQAEggEAfU7sejXBcy8e7eIS/8Q+Q/qTfo/nm9IHAC35
# Vbij99tak+6xpPfJdVKOBvSZf9a8s1R4mw0wKxGHazPV+b3aEhKKWb7EozId+bo6
# 8suQeJe7hBb+LMhSWEPZpJvZjvmeNaOzcKjxuw5O8wIRRmOUwZWQ7Z5naOzB4K2w
# lTJXOWDHvob7PXFQVmXqzuhPrpGWiHxbG8mH9RjJI8vF7D01gTxWNoxHnZeXWMaV
# CHicuCj2iDp2VOnHiclIKfoH0o5UoJJi1MlWQRrR4c7/rdt6AyipEz1D2EzKJBNK
# sg+fzaaODJGHgAq1yK5ht/kUE39sxpQaMMc8a4SV+d4c3YtmVaGCEvEwghLtBgor
# BgEEAYI3AwMBMYIS3TCCEtkGCSqGSIb3DQEHAqCCEsowghLGAgEDMQ8wDQYJYIZI
# AWUDBAIBBQAwggFVBgsqhkiG9w0BCRABBKCCAUQEggFAMIIBPAIBAQYKKwYBBAGE
# WQoDATAxMA0GCWCGSAFlAwQCAQUABCC1izr1C0b14sRadazqKDZpaFHEHOOepurB
# nP5wPdOJtAIGYYHv3+kSGBMyMDIxMTEwODE4MjYzOS4wODdaMASAAgH0oIHUpIHR
# MIHOMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQL
# EyBNaWNyb3NvZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046Rjc3Ri1FMzU2LTVCQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2Wggg5EMIIE9TCCA92gAwIBAgITMwAAAV6dKcdfhwWh
# 6gAAAAABXjANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDAeFw0yMTAxMTQxOTAyMTlaFw0yMjA0MTExOTAyMTlaMIHOMQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3NvZnQg
# T3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046
# Rjc3Ri1FMzU2LTVCQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNl
# cnZpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCa0yODkHoZ96Cq
# ds7oelj9mYm/w8cP7Ky3nsk2/Xnez1/ny4O8wQNMpeorxdp+pWrhh/FuxAcETxL+
# 2Qkl8F4GGehhmh/GlPjqw1wG3OAV0zuV5yxsEm2snvUdvrkB3QiZmjLc/5RAVlCu
# cbx6I9E1K1zmXWf77+06jFgOIdQE9cPyQUeJB7VdYvClnZUPnWV/4DR6QO9iKC6D
# pqSJmxkc3BkOGdis6uHjAfcI2hUVdSRf8M9YSxSIxrZVN3ho0QYgRBFSO1BDDEry
# OKyvgnywCGZ1C7u0s5SH6klN0dKUjVGocKVnQogenysyKveGfvfPPJqELqPeUQD5
# sx0FtTCNAgMBAAGjggEbMIIBFzAdBgNVHQ4EFgQUqnJ8ug3dS+VUwhAAns5UeNX4
# HyswHwYDVR0jBBgwFoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBL
# oEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
# BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNU
# aW1TdGFQQ0FfMjAxMC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAK
# BggrBgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAQEAfyH8WYTGJATKkZl54f1YreG3
# 8coqAJa+xydVw0h0yL0cAw9Txq9LqWRP766yP0Df9Vourw3Cppydq+14+qVmTman
# PQafrgb6T2rpbnuLLbt06ik3PRbtiuYm3LaReKBz32fiCngoaKfjJPYOzeZZR879
# Ggg4mjNMNmgE96490B0EvIo50Of6obc8KNQKFJ1dctrq1sF+Wh3VM2qHgCa7539n
# nvPSn+MnI48mnzSUlKf6mlwZW4zLvdLzbmybLXUsTrb8HMXnhz+mWmG05dnDpWuH
# KJIj1PgVIyGQP7fyGX2KGszBpgbS1hSWXQvS2Flpiy7DSdlttapHkkqRAMOKZjCC
# BnEwggRZoAMCAQICCmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1
# NVoXDTI1MDcwMTIxNDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/
# aZRrdFQQ1aUKAIKF++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxh
# MFmxMEQP8WCIhFRDDNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhH
# hjKEHnRhZ5FfgVSxz5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tk
# iVBisV39dx898Fd1rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox
# 8NpOBpG2iAg16HgcsOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJN
# AgMBAAGjggHmMIIB4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIox
# kPNDe3xGG8UzaFqFbVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAG
# A1UdIAEB/wSBlTCBkjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAG
# CCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEA
# dABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXED
# PZ2joSFvs+umzPUxvs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgr
# UYJEEvu5U4zM9GASinbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c
# 8pl5SpFSAK84Dxf1L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFw
# nzJKJ/1Vry/+tuWOM7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFt
# w5yjojz6f32WapB4pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk
# 7Pf0v35jWSUPei45V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9d
# dJgiCGHasFAeb73x4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zG
# y9iCtHLNHfS4hQEegPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3
# yKxO2ii4sanblrKnQqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7c
# RDyXUHHXodLFVeNp3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wkn
# HNWzfjUeCLraNtvTX4/edIhJEqGCAtIwggI7AgEBMIH8oYHUpIHRMIHOMQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSkwJwYDVQQLEyBNaWNyb3Nv
# ZnQgT3BlcmF0aW9ucyBQdWVydG8gUmljbzEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046Rjc3Ri1FMzU2LTVCQUUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAFZJj1f/IWVUvRc27aF9sd2dsWMqoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDlM66EMCIYDzIwMjExMTA4MTgxMTE2WhgPMjAyMTExMDkxODExMTZaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOUzroQCAQAwCgIBAAICFjICAf8wBwIBAAIC
# EYkwCgIFAOU1AAQCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQDEaMBfZ/Yv
# Pxb7FtSrW8NAKhLF5hRVr9sdsCigqYYSoU7zR+lZS1btLQo6QVzhYP0fMdC8a+cC
# nlxXiPR5Sruy8Z5cvyXpYwCwBUAKa+kGp1RNN7LcDj3DSBiET5+hllk33m8S4IzX
# Y1YDDUYEVXFcMTlFrixBO3sXNUm1NIHP/TGCAw0wggMJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABXp0px1+HBaHqAAAAAAFeMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIHEZQsAzLuq1UujhDSkRXpOpOZLlG+1euoe/vlRrsESIMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgfuWE7JTUl47gfuZkA0ykZDO6a5HsIV53
# r16S7/ES0+IwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAV6dKcdfhwWh6gAAAAABXjAiBCDgdq6D+LQ97IJdVdc4YeTqcTOHU3Y2lxtT
# +Ccl0S5ygDANBgkqhkiG9w0BAQsFAASCAQA4e5PmHU0XArksfoXgC15JvYTA7lBW
# O3sDydIN8iqTUmR8eJF830C3ntvVJqe5HwslYCCCskGjfiF2xobNwSZV3/BuSm1b
# PZAlRlhilSqGEZFoqp3aH/m2UCIrqfpc8acVYdhV94nPW+8plOYOsguZfqWEHt0I
# 7XYiVOLUK5iV7R7SGLB10bRvP8ZbVZxG6Ft56AzQG/ymq1rN+EKFl1ivklngsH4E
# y4/f71HEsfpt+gqJs9uBjkfA/tbH6iwY6blspl4grlQkSm5WoBVJoSPsSebvRF6P
# qTZVHufbdZHDiJlNsKYnZtlnS/CefbJQrt+2qw1SXH0nkaiQdWDBvora
# SIG # End signature block
