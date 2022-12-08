Configuration AzureTagtoMDETag
{
    Import-DscResource -ModuleName PSDscResources

    Node localhost
    {
        Script RegPathMDEGroup
        {
            SetScript = {
                New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging' -Force
                New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging' -Name  'Group' -Value "MDCOnboarded" -PropertyType 'String' -Force
            }
            TestScript = { Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging' }
            GetScript = { @{ Result = (Get-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging').Name } }
        }

        Registry  MDETagKey
        {
            DependsOn = '[Script]RegPathMDEGroup'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
            ValueName = ''
            Ensure = "Present"
        }

        Script AzureTagtoMDETagRegValue
        {
            DependsOn = '[Registry]MDETagKey'
            SetScript = {
                $metadata = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" #| ConvertTo-Json -Depth 64
                $rawtags = $metadata.compute.tags

                # Change value of parameter -Pattern ex. "Project:" for Azure tag you want to be placed for MDE Tag
                $tag = $rawtags.Split(";") | Select-String -Pattern "project:"

                New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging' -Name  'Group' -Value $tag -PropertyType 'String' -Force

            }
            TestScript = {
                $state = [scriptblock]::Create($GetScript).Invoke()

                $azmetadata = Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" #| ConvertTo-Json -Depth 64
                $rawaztags = $azmetadata.compute.tags

                # Change value of parameter -Pattern ex. "Project:" for Azure tag you want to be placed for MDE Tag
                $aztag = $rawaztags.Split(";") | Select-String -Pattern "project:"


                if( $state.Result -eq $aztag )
                {
                    Write-Verbose -Message 'True'
                    return $true
                }
                Write-Verbose -Message 'False'
                return $false
            
            }

            GetScript = {
                $currentItem = Get-ItemPropertyValue -Name Group 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
                return @{ 'Result' = "$currentItem" }
            }
        }
    }
}