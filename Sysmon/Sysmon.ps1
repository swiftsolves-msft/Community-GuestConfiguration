configuration Sysmon
{
    Import-DscResource -ModuleName PSDscResources
    Node localhost
    {
        Registry SysmonConfig
        {
            Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sysmon'
            Ensure = 'Present'
            ValueName = 'SysmonVer'
            ValueType = 'DWord'
            ValueData = '1'
            Force = $true
        }
        WindowsProcess SysmonDownload {
            DependsOn = '[Registry]SysmonConfig'
            Path      = 'C:\Windows\System32\bitsadmin.exe'
            Arguments = "/transfer myDownloadJob1 /download /priority foreground https://download.sysinternals.com/files/Sysmon.zip C:\Sysmon.zip"
            Ensure    = 'Present'
        }
        Archive ArchiveSysmon
        {
            DependsOn = '[WindowsProcess]SysmonDownload'
            Path = 'C:\Sysmon.zip'
            Destination = 'C:\'
            Ensure = 'Present'
            Force = $true
        }
        WindowsProcess SysmonConfigDownload {
            DependsOn = '[Archive]ArchiveSysmon'
            Path      = 'C:\Windows\System32\bitsadmin.exe'
            Arguments = "/transfer myDownloadJob2 /download /priority foreground https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-mde-augment.xml C:\sysmonconfig-mde-augment.xml"
            Ensure    = 'Present'
        }
        WindowsProcess SysmonInstall {
            DependsOn = '[WindowsProcess]SysmonConfigDownload'
            Path      = 'C:\Sysmon64.exe'
            Arguments = '-accepteula -i C:\sysmonconfig-mde-augment.xml'
            Ensure    = 'Present'
        }
    }
}