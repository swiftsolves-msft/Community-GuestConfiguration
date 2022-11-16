configuration Sophos

{ 
    Import-DscResource -ModuleName PSDSCResources
    Node localhost
    {
        Service SophosEndpoint
        {
            Name        = "Sophos Endpoint Defense Service"
            StartupType = "Automatic"
            State       = "Running"
            Ensure      = "Absent"
        }
        WindowsProcess SophosDownload {
            Path      = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
            Arguments = "-c `"invoke-webrequest 'https://dzr-api-amzn-us-west-2-fa88.api-upe.p.hmr.sophos.com/api/download/111fcffd6e74e774c687eff623fa6be9/SophosSetup.exe' -outfile c:\SophosSetup.exe `""
            Ensure    = 'Present'
        }
        WindowsProcess SophosInstall {
            DependsOn = '[WindowsProcess]SophosDownload'
            Path      = 'C:\SophosSetup.exe'
            Arguments = '--quiet'
            Ensure    = 'Present'
        }
    }
}