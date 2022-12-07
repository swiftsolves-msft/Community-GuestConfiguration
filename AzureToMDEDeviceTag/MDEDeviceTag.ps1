configuration MDEDeviceTag
{
    Import-DscResource -ModuleName PSDscResources
    Node localhost
    {
        Registry MDEDeviceTag
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging'
            Ensure = 'Present'
            ValueName = 'Group'
            ValueType = 'String'
            ValueData = 'MDCOnboardAzure'
            Force = $true
        }
    }
}