configuration WDAVPassive
{
    Import-DscResource -ModuleName PSDscResources
    Node localhost
    {
        Service ApexOneNTRealTimeScan
        {
            Name        = "ntrtscan"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Present"
        }
        Registry WDAVPassiveValueSet
        {
            DependsOn = '[Service]ApexOneNTRealTimeScan'
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection'
            Ensure = 'Present'
            ValueName = 'ForceDefenderPassiveMode'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }
    }
}